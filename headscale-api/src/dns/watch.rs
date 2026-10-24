//! Filesystem event wakeups supplement content polling. Watching both the path
//! and its parent keeps atomic replacements observable without trusting mtimes.

use std::{io, path::Path};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use std::{
        ffi::OsString,
        os::fd::{AsFd, AsRawFd, RawFd},
        path::{Path, PathBuf},
    };

    use nix::sys::inotify::{AddWatchFlags as Flags, InitFlags, Inotify, WatchDescriptor};
    use tokio::io::unix::AsyncFd;

    use super::io;

    struct FileDescriptor(Inotify);

    impl AsRawFd for FileDescriptor {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_fd().as_raw_fd()
        }
    }

    pub(super) struct Events {
        fd: AsyncFd<FileDescriptor>,
        path: PathBuf,
        parent: PathBuf,
        name: OsString,
        file_watch: Option<WatchDescriptor>,
        parent_watch: Option<WatchDescriptor>,
    }

    impl Events {
        // tokio deprecated `AsyncFd::new` for the `unsafe` `register`, whose only
        // precondition is that the descriptor stays open for the wrapper's life.
        // `FileDescriptor` owns the inotify fd, so that holds; the workspace
        // denies `unsafe_code`, so the safe (deprecated) constructor stays.
        #[allow(deprecated)]
        pub(super) fn new(path: &Path) -> io::Result<Self> {
            let fd = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)
                .map_err(io::Error::from)?;
            let parent = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let name = path.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "extra-records path has no file name",
                )
            })?;
            let mut events = Self {
                fd: AsyncFd::new(FileDescriptor(fd))?,
                path: path.to_owned(),
                parent: parent.to_owned(),
                name: name.to_owned(),
                file_watch: None,
                parent_watch: None,
            };
            events.refresh();
            if events.file_watch.is_none() && events.parent_watch.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "extra-records watch path unavailable",
                ));
            }
            Ok(events)
        }

        pub(super) fn refresh(&mut self) {
            let watch = &self.fd.get_ref().0;
            let flags = Flags::IN_MODIFY
                | Flags::IN_ATTRIB
                | Flags::IN_CLOSE_WRITE
                | Flags::IN_DELETE_SELF
                | Flags::IN_MOVE_SELF;
            let file = watch.add_watch(&self.path, flags).ok();
            if self.file_watch != file {
                if let Some(old) = self.file_watch.take() {
                    let _ = watch.rm_watch(old);
                }
                self.file_watch = file;
            }
            let parent = watch
                .add_watch(
                    &self.parent,
                    flags
                        | Flags::IN_CREATE
                        | Flags::IN_MOVED_TO
                        | Flags::IN_MOVED_FROM
                        | Flags::IN_DELETE,
                )
                .ok();
            if self.parent_watch != parent {
                if let Some(old) = self.parent_watch.take() {
                    let _ = watch.rm_watch(old);
                }
                self.parent_watch = parent;
            }
        }

        pub(super) async fn changed(&self) -> io::Result<()> {
            loop {
                let mut ready = self.fd.readable().await?;
                let events = match ready
                    .try_io(|fd| fd.get_ref().0.read_events().map_err(io::Error::from))
                {
                    Ok(result) => result?,
                    Err(_) => continue,
                };
                for event in events {
                    if event.mask.contains(Flags::IN_Q_OVERFLOW)
                        || Some(event.wd) == self.file_watch
                        || Some(event.wd) == self.parent_watch
                            && (event.name.as_ref() == Some(&self.name) || event.name.is_none())
                    {
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "watchos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
))]
mod platform {
    use std::{
        fs::{File, OpenOptions},
        os::{
            fd::{AsFd, AsRawFd, RawFd},
            unix::fs::MetadataExt,
        },
        path::{Path, PathBuf},
        sync::atomic::{AtomicBool, Ordering},
    };

    use nix::{
        fcntl::{FcntlArg, FdFlag, fcntl},
        sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue},
    };
    use tokio::io::{Interest, unix::AsyncFd};

    use super::io;

    struct Queue(Kqueue);

    impl AsRawFd for Queue {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_fd().as_raw_fd()
        }
    }

    struct Vnode {
        // Closing this owned descriptor also removes its vnode filter.
        _file: File,
        identity: (u64, u64),
    }

    pub(super) struct Events {
        queue: AsyncFd<Queue>,
        path: PathBuf,
        parent: PathBuf,
        file_watch: Option<Vnode>,
        parent_watch: Option<Vnode>,
        reopen: AtomicBool,
    }

    impl Events {
        // See the inotify constructor: `Queue` owns the kqueue descriptor, and
        // tokio's non-deprecated registration is `unsafe`, which the workspace
        // denies.
        #[allow(deprecated)]
        pub(super) fn new(path: &Path) -> io::Result<Self> {
            let queue = Kqueue::new().map_err(io::Error::from)?;
            fcntl(
                queue.as_fd().as_raw_fd(),
                FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
            )
            .map_err(io::Error::from)?;
            let parent = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let mut events = Self {
                // Kqueue descriptors support read readiness, not write readiness.
                queue: AsyncFd::with_interest(Queue(queue), Interest::READABLE)?,
                path: path.to_owned(),
                parent: parent.to_owned(),
                file_watch: None,
                parent_watch: None,
                reopen: AtomicBool::new(false),
            };
            events.refresh();
            if events.file_watch.is_none() && events.parent_watch.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "extra-records watch path unavailable",
                ));
            }
            Ok(events)
        }

        pub(super) fn refresh(&mut self) {
            if self.reopen.swap(false, Ordering::AcqRel) {
                self.file_watch = None;
                self.parent_watch = None;
            }
            let queue = &self.queue.get_ref().0;
            refresh_vnode(queue, &self.path, &mut self.file_watch);
            refresh_vnode(queue, &self.parent, &mut self.parent_watch);
        }

        pub(super) async fn changed(&self) -> io::Result<()> {
            loop {
                let mut ready = self.queue.readable().await?;
                // A spurious readiness (WouldBlock) falls through to wait again.
                if let Ok(result) = ready.try_io(|queue| {
                    let empty = KEvent::new(
                        0,
                        EventFilter::EVFILT_VNODE,
                        EventFlag::empty(),
                        FilterFlag::empty(),
                        0,
                        0,
                    );
                    let mut events = [empty; 8];
                    let count = queue
                        .get_ref()
                        .0
                        .kevent(
                            &[],
                            &mut events,
                            Some(nix::libc::timespec {
                                tv_sec: 0,
                                tv_nsec: 0,
                            }),
                        )
                        .map_err(io::Error::from)?;
                    if count == 0 {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    for event in &events[..count] {
                        if event.flags().contains(EventFlag::EV_ERROR) && event.data() != 0 {
                            return Err(io::Error::from_raw_os_error(event.data() as i32));
                        }
                        if event.fflags().intersects(
                            FilterFlag::NOTE_DELETE
                                | FilterFlag::NOTE_RENAME
                                | FilterFlag::NOTE_REVOKE,
                        ) {
                            self.reopen.store(true, Ordering::Release);
                        }
                    }
                    Ok(())
                }) {
                    return result;
                }
            }
        }
    }

    fn refresh_vnode(queue: &Kqueue, path: &Path, slot: &mut Option<Vnode>) {
        let Ok(metadata) = std::fs::metadata(path) else {
            *slot = None;
            return;
        };
        let identity = (metadata.dev(), metadata.ino());
        if slot
            .as_ref()
            .is_some_and(|watch| watch.identity == identity)
        {
            return;
        }
        // Keep the old vnode alive until its replacement has been registered.
        // Apple O_EVTONLY avoids requiring directory read permission; other
        // supported BSDs use ordinary read descriptors as fsnotify does.
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "visionos"
        ))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(nix::libc::O_EVTONLY);
        }
        let replacement = (|| -> io::Result<Vnode> {
            let file = options.open(path)?;
            let metadata = file.metadata()?;
            let event = KEvent::new(
                file.as_raw_fd() as _,
                EventFilter::EVFILT_VNODE,
                EventFlag::EV_ADD | EventFlag::EV_CLEAR,
                FilterFlag::NOTE_WRITE
                    | FilterFlag::NOTE_EXTEND
                    | FilterFlag::NOTE_ATTRIB
                    | FilterFlag::NOTE_LINK
                    | FilterFlag::NOTE_RENAME
                    | FilterFlag::NOTE_DELETE
                    | FilterFlag::NOTE_REVOKE,
                0,
                0,
            );
            queue
                .kevent(
                    &[event],
                    &mut [],
                    Some(nix::libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    }),
                )
                .map_err(io::Error::from)?;
            Ok(Vnode {
                _file: file,
                identity: (metadata.dev(), metadata.ino()),
            })
        })();
        *slot = replacement.ok();
    }
}

pub(super) struct Events {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "watchos",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    inner: platform::Events,
}

impl Events {
    pub(super) fn new(path: &Path) -> Option<Self> {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            platform::Events::new(path).ok().map(|inner| Self { inner })
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        {
            let _ = path;
            None
        }
    }

    pub(super) fn refresh(&mut self) {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        self.inner.refresh();
    }

    pub(super) async fn changed(&self) -> io::Result<()> {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        {
            self.inner.changed().await
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "watchos",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        )))]
        {
            std::future::pending().await
        }
    }
}
