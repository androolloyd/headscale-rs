use crate::codec::UserError;
use crate::error::Reason;
use crate::proto::*;
use std::task::{Context, Poll};

#[derive(Debug)]
pub(crate) struct Settings {
    /// Our local SETTINGS sync state with the remote.
    local: Local,
    /// Default-mode SETTINGS frame pending processing. The ACK must be written to
    /// the socket first then the settings applied **before** receiving any
    /// further frames.
    remote: Option<frame::Settings>,
    /// Whether the connection has received the initial SETTINGS frame from the
    /// remote peer.
    has_received_remote_initial_settings: bool,
    /// Go applies peer settings immediately and coalesces pending ACKs.
    #[cfg(feature = "go-server-lifecycle")]
    go_pending_ack: Option<bool>,
}

#[derive(Debug)]
enum Local {
    /// We want to send these SETTINGS to the remote when the socket is ready.
    ToSend(frame::Settings),
    /// We have sent these SETTINGS and are waiting for the remote to ACK
    /// before we apply them.
    WaitingAck(frame::Settings),
    /// Our local settings are in sync with the remote.
    Synced,
}

impl Settings {
    /// Go's client acquires its writer before applying peer settings, then
    /// writes and flushes one ACK before its reader advances. The caller owns
    /// that writer/flush barrier and ignores ACK write/flush errors as Go does;
    /// this path never enables server coalescing.
    #[cfg(feature = "go-client-idle")]
    pub(crate) fn recv_go_client_settings<T, B, C, P>(
        &mut self,
        frame: frame::Settings,
        codec: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Result<bool, Error>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if frame.is_ack() {
            self.recv_settings(frame, codec, streams)?;
            return Ok(false);
        }
        debug_assert!(self.remote.is_none());
        let is_initial = self.mark_remote_initial_settings_as_received();
        streams.apply_remote_settings(&frame, is_initial)?;
        if let Some(value) = frame.header_table_size() {
            codec.set_send_header_table_size(value as usize);
        }
        if let Some(value) = frame.max_frame_size() {
            codec.set_max_send_frame_size(value as usize);
        }
        Ok(true)
    }

    pub(crate) fn new(local: frame::Settings) -> Self {
        Settings {
            // Default handshakes already flushed the initial SETTINGS;
            // native Go handshakes may still have that frame queued.
            local: Local::WaitingAck(local),
            remote: None,
            has_received_remote_initial_settings: false,
            #[cfg(feature = "go-server-lifecycle")]
            go_pending_ack: None,
        }
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn enable_go_native(&mut self) {
        self.go_pending_ack = Some(false);
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn go_pending_controls(&self) -> usize {
        usize::from(self.go_pending_ack == Some(true))
    }

    pub(crate) fn recv_settings<T, B, C, P>(
        &mut self,
        frame: frame::Settings,
        codec: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Result<(), Error>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        if frame.is_ack() {
            match &self.local {
                Local::WaitingAck(local) => {
                    tracing::debug!("received settings ACK; applying {:?}", local);

                    if let Some(max) = local.max_frame_size() {
                        codec.set_max_recv_frame_size(max as usize);
                    }

                    if let Some(max) = local.max_header_list_size() {
                        codec.set_max_recv_header_list_size(max as usize);
                    }

                    if let Some(val) = local.header_table_size() {
                        codec.set_recv_header_table_size(val as usize);
                    }

                    streams.apply_local_settings(local)?;
                    self.local = Local::Synced;
                    Ok(())
                }
                Local::ToSend(..) | Local::Synced => {
                    // We haven't sent any SETTINGS frames to be ACKed, so
                    // this is very bizarre! Remote is either buggy or malicious.
                    proto_err!(conn: "received unexpected settings ack");
                    Err(Error::library_go_away(Reason::PROTOCOL_ERROR))
                }
            }
        } else {
            #[cfg(feature = "go-server-lifecycle")]
            if self.go_pending_ack.is_some() {
                let is_initial = self.mark_remote_initial_settings_as_received();
                streams.apply_remote_settings(&frame, is_initial)?;
                if let Some(val) = frame.header_table_size() {
                    codec.set_send_header_table_size(val as usize);
                }
                if let Some(val) = frame.max_frame_size() {
                    codec.set_max_send_frame_size(val as usize);
                }
                self.go_pending_ack = Some(true);
                return Ok(());
            }
            // We always ACK before reading more frames, so `remote` should
            // always be none!
            assert!(self.remote.is_none());
            self.remote = Some(frame);
            Ok(())
        }
    }

    pub(crate) fn send_settings(&mut self, frame: frame::Settings) -> Result<(), UserError> {
        assert!(!frame.is_ack());
        match &self.local {
            Local::ToSend(..) | Local::WaitingAck(..) => Err(UserError::SendSettingsWhilePending),
            Local::Synced => {
                tracing::trace!("queue to send local settings: {:?}", frame);
                self.local = Local::ToSend(frame);
                Ok(())
            }
        }
    }

    /// Sets `true` to `self.has_received_remote_initial_settings`.
    /// Returns `true` if this method is called for the first time.
    /// (i.e. it is the initial SETTINGS frame from the remote peer)
    fn mark_remote_initial_settings_as_received(&mut self) -> bool {
        let has_received = self.has_received_remote_initial_settings;
        self.has_received_remote_initial_settings = true;
        !has_received
    }

    pub(crate) fn poll_send<T, B, C, P>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, B>,
        streams: &mut Streams<C, P>,
    ) -> Poll<Result<(), Error>>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
        C: Buf,
        P: Peer,
    {
        #[cfg(feature = "go-server-lifecycle")]
        if self.go_pending_ack == Some(true) {
            if !dst.poll_ready(cx)?.is_ready() {
                return Poll::Pending;
            }
            dst.buffer(frame::Settings::ack().into())
                .expect("invalid settings frame");
            self.go_pending_ack = Some(false);
        }
        if let Some(settings) = self.remote.clone() {
            if !dst.poll_ready(cx)?.is_ready() {
                return Poll::Pending;
            }

            // Create an ACK settings frame
            let frame = frame::Settings::ack();

            // Buffer the settings frame
            dst.buffer(frame.into()).expect("invalid settings frame");

            tracing::trace!("ACK sent; applying settings");

            let is_initial = self.mark_remote_initial_settings_as_received();
            streams.apply_remote_settings(&settings, is_initial)?;

            if let Some(val) = settings.header_table_size() {
                dst.set_send_header_table_size(val as usize);
            }

            if let Some(val) = settings.max_frame_size() {
                dst.set_max_send_frame_size(val as usize);
            }
        }

        self.remote = None;

        match &self.local {
            Local::ToSend(settings) => {
                if !dst.poll_ready(cx)?.is_ready() {
                    return Poll::Pending;
                }

                // Buffer the settings frame
                dst.buffer(settings.clone().into())
                    .expect("invalid settings frame");
                tracing::trace!("local settings sent; waiting for ack: {:?}", settings);

                self.local = Local::WaitingAck(settings.clone());
            }
            Local::WaitingAck(..) | Local::Synced => {}
        }

        Poll::Ready(Ok(()))
    }
}
