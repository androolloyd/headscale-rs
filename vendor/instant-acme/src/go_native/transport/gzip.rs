// Copyright 2009 The Go Authors. All rights reserved.
// Adapted from Go 1.26.9 compress/gzip/gunzip.go; see LICENSE-GO.

//! Lazy native gzip bodies. Compressed input and decoded output are bounded
//! chunks; consumers retain their existing first-value/limited-read policies.

use std::{
    error::Error,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    BytesBody,
    limits::{MAX_RESPONSE_BODY, body_too_large},
};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;

mod inflate;
mod read_size;

type BodyError = Box<dyn Error + Send + Sync + 'static>;

pub(super) enum NativeBody {
    Raw(Option<Incoming>),
    Gzip(Box<Reader>),
    Buffered(Bytes),
}

impl NativeBody {
    pub(super) fn buffered(bytes: Bytes) -> Self {
        Self::Buffered(bytes)
    }
    pub(super) fn new(body: Incoming, gzip: bool) -> Self {
        if gzip {
            Self::Gzip(Box::new(Reader::new(body)))
        } else {
            Self::Raw(Some(body))
        }
    }

    async fn read(&mut self, maximum: usize) -> Read {
        match self {
            Self::Raw(Some(body)) => {
                let read = std::future::poll_fn(|cx| body.go_poll_read(cx, maximum)).await;
                Read {
                    data: read.data,
                    error: read.error.map(|error| Box::new(error) as BodyError),
                    eof: read.eof,
                }
            }
            Self::Raw(None) => Read {
                data: Bytes::new(),
                error: None,
                eof: true,
            },
            Self::Gzip(reader) => reader.read(maximum).await,
            Self::Buffered(bytes) => {
                let eof = bytes.is_empty();
                let count = maximum.min(bytes.len());
                Read {
                    data: bytes.split_to(count),
                    error: None,
                    eof,
                }
            }
        }
    }

    /// Read until EOF or `limit` bytes (of decoded output, for a gzip body),
    /// whichever comes first; there is deliberately no unbounded variant.
    async fn collect(&mut self, limit: usize, partial: bool) -> Result<Bytes, BodyError> {
        let mut output = Vec::new();
        let mut sizes = read_size::ReadAll::new();
        loop {
            let maximum = (limit - output.len()).min(sizes.maximum());
            if maximum == 0 {
                return Ok(Bytes::from(output));
            }
            let read = self.read(maximum).await;
            output.extend_from_slice(&read.data);
            if let Some(error) = read.error {
                return if partial {
                    Ok(Bytes::from(output))
                } else {
                    Err(error)
                };
            }
            if read.eof {
                return Ok(Bytes::from(output));
            }
            sizes
                .advance(read.data.len())
                .ok_or_else(|| body_error("ReadAll buffer size overflow"))?;
        }
    }
}

impl Body for NativeBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match self.get_mut() {
            Self::Raw(Some(body)) => Pin::new(body).poll_frame(cx).map(|frame| {
                frame.map(|frame| frame.map_err(|error| Box::new(error) as BodyError))
            }),
            Self::Raw(None) => Poll::Ready(None),
            Self::Gzip(body) => body.poll_frame(cx),
            Self::Buffered(bytes) => Poll::Ready(if bytes.is_empty() {
                None
            } else {
                Some(Ok(Frame::data(std::mem::take(bytes))))
            }),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Raw(Some(body)) => body.size_hint(),
            Self::Raw(None) => SizeHint::with_exact(0),
            Self::Gzip(_) => SizeHint::default(),
            Self::Buffered(bytes) => SizeHint::with_exact(bytes.len() as u64),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Raw(Some(body)) => body.is_end_stream(),
            Self::Raw(None) => true,
            Self::Gzip(body) => body.finished,
            Self::Buffered(bytes) => bytes.is_empty(),
        }
    }
}

#[async_trait]
impl BytesBody for NativeBody {
    async fn into_bytes(&mut self) -> Result<Bytes, BodyError> {
        // One byte past the bound proves the body is too large without ever
        // buffering more; `collect` limits the DECODED output of a gzip body
        // (its reads are clipped to the remaining allowance), so a small
        // compressed bomb stops at the same bound as a plain stream.
        let result = match self.collect(MAX_RESPONSE_BODY + 1, false).await {
            Ok(body) if body.len() > MAX_RESPONSE_BODY => Err(body_too_large(MAX_RESPONSE_BODY)),
            result => result,
        };
        let _ = self.close_native().await;
        result
    }

    async fn into_bytes_limited(&mut self, limit: usize) -> Result<Bytes, BodyError> {
        let result = self.collect(limit, false).await;
        let _ = self.close_native().await;
        result
    }

    async fn into_bytes_partial(&mut self) -> Bytes {
        // A diagnostic prefix: whatever arrives up to the bound is kept, the
        // rest of an oversized error body is never read.
        let result = self
            .collect(MAX_RESPONSE_BODY, true)
            .await
            .unwrap_or_default();
        let _ = self.close_native().await;
        result
    }

    async fn close_native(&mut self) -> Result<(), BodyError> {
        match self {
            Self::Raw(body) => {
                let result = if let Some(incoming) = body.as_mut() {
                    std::future::poll_fn(|cx| incoming.go_poll_close(cx))
                        .await
                        .map_err(|error| Box::new(error) as BodyError)
                } else {
                    Ok(())
                };
                *body = None;
                result
            }
            Self::Gzip(reader) => {
                let result = std::future::poll_fn(|cx| reader.body.go_poll_close(cx))
                    .await
                    .map_err(|error| Box::new(error) as BodyError);
                reader.finished = true;
                result
            }
            Self::Buffered(_) => Ok(()),
        }
    }

    async fn discard_bytes_limited(&mut self, limit: usize) -> Result<(), BodyError> {
        let result = async {
            let mut remaining = limit;
            while remaining > 0 {
                // io.CopyN's 32KiB copy buffer is clipped by LimitedReader.N.
                let read = self.read(remaining.min(32 * 1024)).await;
                remaining -= read.data.len();
                if remaining == 0 {
                    return Ok(());
                }
                if let Some(error) = read.error {
                    return Err(error);
                }
                if read.eof {
                    break;
                }
            }
            Ok(())
        }
        .await;
        let _ = self.close_native().await;
        result
    }

    async fn into_first_json_value(&mut self) -> Result<Bytes, BodyError> {
        let result = async {
            let mut scanner = super::super::json_prefix::Scanner::new();
            let mut output = Vec::new();
            // Track Go's logical Decoder buffer capacity independently of
            // the Rust allocator's chosen capacity (stream.go refill).
            let mut capacity = 0usize;
            loop {
                if capacity - output.len() < 512 {
                    capacity = capacity
                        .checked_mul(2)
                        .and_then(|cap| cap.checked_add(512))
                        .ok_or_else(|| body_error("JSON decoder buffer size overflow"))?;
                }
                // Never request more than one byte past the bound: a value
                // that has not completed within MAX_RESPONSE_BODY bytes is
                // rejected without buffering (or decoding) anything further.
                let want = (capacity - output.len()).min(MAX_RESPONSE_BODY + 1 - output.len());
                let read = self.read(want).await;
                if let Some(length) = scanner.feed(&read.data) {
                    if output.len() + length > MAX_RESPONSE_BODY {
                        return Err(body_too_large(MAX_RESPONSE_BODY));
                    }
                    output.extend_from_slice(&read.data[..length]);
                    return Ok(Bytes::from(output));
                }
                output.extend_from_slice(&read.data);
                if output.len() > MAX_RESPONSE_BODY {
                    return Err(body_too_large(MAX_RESPONSE_BODY));
                }
                // As in Go readValue, syntax and completed values found
                // in n bytes take priority over the same Read's error.
                if let Some(error) = read.error {
                    return Err(error);
                }
                if read.eof {
                    return Ok(Bytes::from(output));
                }
            }
        }
        .await;
        let _ = self.close_native().await;
        result
    }
}

struct Read {
    data: Bytes,
    error: Option<BodyError>,
    eof: bool,
}

pub(super) struct Reader {
    body: Incoming,
    input: Bytes,
    decoder: Decoder,
    eof: bool,
    transport_error: Option<BodyError>,
    pending_error: Option<BodyError>,
    finished: bool,
}

impl Reader {
    fn new(body: Incoming) -> Self {
        Self {
            body,
            input: Bytes::new(),
            decoder: Decoder::new(),
            eof: false,
            transport_error: None,
            pending_error: None,
            finished: false,
        }
    }

    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let read = match self.poll_read(cx, 16 * 1024) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(read) => read,
        };
        if !read.data.is_empty() {
            self.pending_error = read.error;
            return Poll::Ready(Some(Ok(Frame::data(read.data))));
        }
        if let Some(error) = read.error {
            return Poll::Ready(Some(Err(error)));
        }
        Poll::Ready(None)
    }

    async fn read(&mut self, maximum: usize) -> Read {
        std::future::poll_fn(|cx| self.poll_read(cx, maximum)).await
    }

    fn poll_read(&mut self, cx: &mut Context<'_>, maximum: usize) -> Poll<Read> {
        if let Some(error) = self.pending_error.take() {
            self.finished = true;
            return Poll::Ready(Read {
                data: Bytes::new(),
                error: Some(error),
                eof: false,
            });
        }
        if self.finished {
            return Poll::Ready(Read {
                data: Bytes::new(),
                error: None,
                eof: true,
            });
        }
        loop {
            let (consumed, event) = self.decoder.read(&self.input, self.eof, maximum);
            self.input.advance(consumed);
            match event {
                Event::Output(output) => {
                    return Poll::Ready(Read {
                        data: output,
                        error: None,
                        eof: false,
                    });
                }
                Event::Done => {
                    self.finished = true;
                    let error = self.transport_error.take();
                    let eof = error.is_none();
                    return Poll::Ready(Read {
                        data: self.decoder.final_output.take().unwrap_or_default(),
                        error,
                        eof,
                    });
                }
                Event::Error(message) => {
                    let error = if message == "unexpected EOF" {
                        self.transport_error
                            .take()
                            .unwrap_or_else(|| body_error(message))
                    } else {
                        body_error(message)
                    };
                    self.finished = true;
                    return Poll::Ready(Read {
                        data: self.decoder.final_output.take().unwrap_or_default(),
                        error: Some(error),
                        eof: false,
                    });
                }
                Event::NeedInput => {
                    match self.body.go_poll_read(cx, self.decoder.input_read_size()) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(read) => {
                            self.input = read.data;
                            if let Some(error) = read.error {
                                self.transport_error = Some(Box::new(error));
                                self.eof = true;
                            }
                            if read.eof {
                                self.eof = true;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn body_error(message: impl Into<String>) -> BodyError {
    Box::new(std::io::Error::other(message.into()))
}

enum Phase {
    Header { bytes: [u8; 10], used: usize },
    ExtraLength { bytes: [u8; 2], used: usize },
    Extra(usize),
    Name(usize),
    Comment(usize),
    HeaderCrc { bytes: [u8; 2], used: usize },
    Data(Box<inflate::Inflater>),
    Trailer { bytes: [u8; 8], used: usize },
}

enum Event {
    NeedInput,
    Output(Bytes),
    Done,
    Error(String),
}

struct Decoder {
    phase: Phase,
    flags: u8,
    crc: u32,
    size: u32,
    input_finished: bool,
    final_output: Option<Bytes>,
    output: Vec<u8>,
}

impl Decoder {
    fn input_read_size(&self) -> usize {
        // gzip wraps transportResponseBody in bufio.NewReader (4096 bytes).
        // An empty buffered Reader bypasses its buffer only for Read(p) where
        // len(p)>=4096, notably large extras and stored DEFLATE dictionary reads.
        let requested = match &self.phase {
            Phase::Extra(remaining) => *remaining,
            Phase::Data(inflater) => inflater.input_read_size(),
            _ => 1,
        };
        requested.max(4096)
    }

    fn new() -> Self {
        Self {
            phase: Phase::Header {
                bytes: [0; 10],
                used: 0,
            },
            flags: 0,
            crc: 0,
            size: 0,
            input_finished: false,
            final_output: None,
            output: vec![0; 16 * 1024],
        }
    }

    fn next_header_field(&mut self) {
        self.phase = if self.flags & 4 != 0 {
            self.flags &= !4;
            Phase::ExtraLength {
                bytes: [0; 2],
                used: 0,
            }
        } else if self.flags & 8 != 0 {
            self.flags &= !8;
            Phase::Name(0)
        } else if self.flags & 16 != 0 {
            self.flags &= !16;
            Phase::Comment(0)
        } else if self.flags & 2 != 0 {
            self.flags &= !2;
            Phase::HeaderCrc {
                bytes: [0; 2],
                used: 0,
            }
        } else {
            self.crc = 0;
            self.size = 0;
            self.input_finished = false;
            Phase::Data(Box::new(inflate::Inflater::new()))
        };
    }

    fn read(&mut self, input: &[u8], eof: bool, maximum: usize) -> (usize, Event) {
        // Go flate.Read returns at most one 32KiB dictionary flush, even when
        // the caller supplies a larger destination.
        let maximum = maximum.min(32 * 1024);
        let mut consumed = 0;
        loop {
            if matches!(self.phase, Phase::Data(_)) {
                if let Some(output) = self.final_output.take() {
                    return (consumed, Event::Output(output));
                }
            }
            let available = &input[consumed..];
            let is_extra_length = matches!(self.phase, Phase::ExtraLength { .. });
            match &mut self.phase {
                Phase::Data(inflater) => {
                    if eof && available.is_empty() && !self.input_finished {
                        inflater.finish_input();
                        self.input_finished = true;
                    }
                    if self.output.len() < maximum {
                        self.output.resize(maximum, 0);
                    }
                    let step = inflater.read(available, &mut self.output[..maximum]);
                    consumed += step.consumed;
                    let output = &self.output[..step.produced];
                    self.crc = crc32(self.crc, output);
                    self.size = self.size.wrapping_add(step.produced as u32);
                    let data = (!output.is_empty()).then(|| Bytes::copy_from_slice(output));
                    match step.status {
                        inflate::Status::Done => {
                            self.final_output = data;
                            self.phase = Phase::Trailer {
                                bytes: [0; 8],
                                used: 0,
                            };
                        }
                        inflate::Status::Corrupt(offset) => {
                            self.final_output = data;
                            return (
                                consumed,
                                Event::Error(format!(
                                    "flate: corrupt input before offset {offset}"
                                )),
                            );
                        }
                        inflate::Status::UnexpectedEof => {
                            self.final_output = data;
                            return (consumed, Event::Error("unexpected EOF".into()));
                        }
                        inflate::Status::NeedInput => {
                            if let Some(output) = data {
                                return (consumed, Event::Output(output));
                            }
                            if consumed == input.len() && !eof {
                                return (consumed, Event::NeedInput);
                            }
                        }
                        inflate::Status::OutputFull => {
                            if let Some(output) = data {
                                return (consumed, Event::Output(output));
                            }
                        }
                    }
                }
                Phase::Header { bytes, used } => {
                    if available.is_empty() {
                        return (
                            consumed,
                            if eof {
                                if *used == 0 {
                                    Event::Done
                                } else {
                                    Event::Error("unexpected EOF".into())
                                }
                            } else {
                                Event::NeedInput
                            },
                        );
                    }
                    let count = (10 - *used).min(available.len());
                    bytes[*used..*used + count].copy_from_slice(&available[..count]);
                    *used += count;
                    consumed += count;
                    if *used == 10 {
                        if bytes[..3] != [0x1f, 0x8b, 8] {
                            return (consumed, Event::Error("gzip: invalid header".into()));
                        }
                        self.flags = bytes[3];
                        self.crc = crc32(0, bytes);
                        self.next_header_field();
                    }
                }
                Phase::ExtraLength { bytes, used } | Phase::HeaderCrc { bytes, used } => {
                    if available.is_empty() {
                        return (
                            consumed,
                            if eof {
                                Event::Error("unexpected EOF".into())
                            } else {
                                Event::NeedInput
                            },
                        );
                    }
                    let count = (2 - *used).min(available.len());
                    bytes[*used..*used + count].copy_from_slice(&available[..count]);
                    *used += count;
                    consumed += count;
                    if *used == 2 {
                        let value = u16::from_le_bytes(*bytes);
                        if is_extra_length {
                            self.crc = crc32(self.crc, bytes);
                            self.phase = Phase::Extra(value as usize);
                        } else {
                            if value != self.crc as u16 {
                                return (consumed, Event::Error("gzip: invalid header".into()));
                            }
                            self.next_header_field();
                        }
                    }
                }
                Phase::Extra(remaining) => {
                    if *remaining == 0 {
                        self.next_header_field();
                        continue;
                    }
                    if available.is_empty() {
                        return (
                            consumed,
                            if eof {
                                Event::Error("unexpected EOF".into())
                            } else {
                                Event::NeedInput
                            },
                        );
                    }
                    let count = (*remaining).min(available.len());
                    self.crc = crc32(self.crc, &available[..count]);
                    *remaining -= count;
                    consumed += count;
                }
                Phase::Name(count) | Phase::Comment(count) => {
                    if *count >= 512 {
                        return (consumed, Event::Error("gzip: invalid header".into()));
                    }
                    if available.is_empty() {
                        return (
                            consumed,
                            if eof {
                                Event::Error("unexpected EOF".into())
                            } else {
                                Event::NeedInput
                            },
                        );
                    }
                    let byte = available[0];
                    self.crc = crc32(self.crc, &[byte]);
                    *count += 1;
                    consumed += 1;
                    if byte == 0 {
                        self.next_header_field();
                    }
                }
                Phase::Trailer { bytes, used } => {
                    if available.is_empty() {
                        return (
                            consumed,
                            if eof {
                                Event::Error("unexpected EOF".into())
                            } else {
                                Event::NeedInput
                            },
                        );
                    }
                    let count = (8 - *used).min(available.len());
                    bytes[*used..*used + count].copy_from_slice(&available[..count]);
                    *used += count;
                    consumed += count;
                    if *used == 8 {
                        if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != self.crc
                            || u32::from_le_bytes(bytes[4..].try_into().unwrap()) != self.size
                        {
                            return (consumed, Event::Error("gzip: invalid checksum".into()));
                        }
                        self.phase = Phase::Header {
                            bytes: [0; 10],
                            used: 0,
                        };
                    }
                }
            }
        }
    }
}

fn crc32(previous: u32, bytes: &[u8]) -> u32 {
    let mut crc = !previous;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
