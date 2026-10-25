//! Bounds for data that a remote ACME or HTTP server controls: how much of a
//! response body is read into memory and how much of it a rendered error
//! string may embed. A hostile or broken server must not be able to make this
//! client allocate (or print) an arbitrary amount, however it frames the body
//! (Content-Length, chunked, HTTP/2 DATA, or compressed).

use std::{error::Error as StdError, fmt};

/// Most bytes of one ACME response body read into memory: directory, nonce,
/// order/authorization JSON and problem documents, and the SDK's whole-body
/// reads.
///
/// The largest legitimate resource is a 100-identifier order or problem
/// document (Let's Encrypt's per-order identifier cap), well under 50 KiB, so
/// this is more than two orders of magnitude of headroom. It is deliberately
/// above the certificate-download cap, which is Go's `maxChainLen*(1<<20)`
/// plus PEM overhead (about 5.2 MiB, `go_certificate` keeps that exact bound),
/// so the SDK's whole-body certificate read is not limited below Go's.
/// x/crypto/acme itself has no bound on these reads (`io.ReadAll` /
/// `json.NewDecoder` on the raw body), which is what this guards against.
pub(crate) const MAX_RESPONSE_BODY: usize = 8 * 1024 * 1024;

/// Most bytes of a remote-controlled problem document that a rendered error
/// (`Display`) may embed, in total across type, detail and subproblems.
///
/// Real problem documents are a few hundred bytes (a Let's Encrypt rate-limit
/// or DNS failure detail is 150-400 bytes; a three-identifier failure with
/// subproblems is about 1 KiB), so 2 KiB shows every real error in full while
/// an 8 MiB detail string cannot become an 8 MiB error string. The complete
/// metadata stays available through the error's structured fields.
pub(crate) const ERROR_DISPLAY_LIMIT: usize = 2048;

/// Error for a response body that is larger than the read bound.
pub(crate) fn body_too_large(limit: usize) -> Box<dyn StdError + Send + Sync + 'static> {
    format!("http: response body too large (limit {limit} bytes)").into()
}

/// A `fmt::Write` that forwards at most a fixed number of bytes (cut on a char
/// boundary) to a formatter and then ignores the rest. `finish` marks a cut.
pub(crate) struct Bounded<'a, 'f> {
    out: &'a mut fmt::Formatter<'f>,
    left: usize,
    cut: bool,
}

impl<'a, 'f> Bounded<'a, 'f> {
    pub(crate) fn new(out: &'a mut fmt::Formatter<'f>, limit: usize) -> Self {
        Self {
            out,
            left: limit,
            cut: false,
        }
    }

    /// Whether the limit has been reached; callers use it to stop iterating.
    pub(crate) fn is_cut(&self) -> bool {
        self.cut
    }

    pub(crate) fn finish(self) -> fmt::Result {
        if self.cut {
            self.out.write_str("... (truncated)")
        } else {
            Ok(())
        }
    }
}

impl fmt::Write for Bounded<'_, '_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.cut {
            return Ok(());
        }
        if text.len() <= self.left {
            self.left -= text.len();
            return self.out.write_str(text);
        }
        let mut end = self.left;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.cut = true;
        self.left = 0;
        self.out.write_str(&text[..end])
    }
}

/// Bounded `Display` for the SDK problem types: `render` writes into a
/// `Bounded` and may check `is_cut` between items.
pub(crate) fn bounded_display(
    formatter: &mut fmt::Formatter<'_>,
    render: impl FnOnce(&mut Bounded<'_, '_>) -> fmt::Result,
) -> fmt::Result {
    let mut out = Bounded::new(formatter, ERROR_DISPLAY_LIMIT);
    render(&mut out)?;
    out.finish()
}

/// Per-thread allocation high-water mark for the bounded-read tests: a test
/// that reads an oversized body on its own current-thread runtime can assert
/// that the whole body was never held in memory, not only that it errored.
#[cfg(test)]
pub(crate) mod alloc_probe {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };

    thread_local! {
        static LIVE: Cell<isize> = const { Cell::new(0) };
        static PEAK: Cell<isize> = const { Cell::new(0) };
        static BASE: Cell<isize> = const { Cell::new(0) };
    }

    pub(crate) struct Counting;

    fn grow(bytes: usize) {
        let bytes = isize::try_from(bytes).unwrap_or(isize::MAX);
        let _ = LIVE.try_with(|live| {
            live.set(live.get().saturating_add(bytes));
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(live.get())));
        });
    }

    fn shrink(bytes: usize) {
        let bytes = isize::try_from(bytes).unwrap_or(isize::MAX);
        let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(bytes)));
    }

    // SAFETY: every method forwards to `System` unchanged; the counters are
    // `const`-initialised thread-locals with no destructor, so counting never
    // allocates or re-enters the allocator.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            grow(layout.size());
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            grow(layout.size());
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            shrink(layout.size());
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            shrink(layout.size());
            grow(new_size);
            unsafe { System.realloc(pointer, layout, new_size) }
        }
    }

    /// Start measuring: the peak is reported relative to what is live now.
    pub(crate) fn reset_peak() {
        let live = LIVE.with(Cell::get);
        BASE.with(|base| base.set(live));
        PEAK.with(|peak| peak.set(live));
    }

    /// Most bytes this thread held above the `reset_peak` baseline.
    pub(crate) fn peak_since_reset() -> usize {
        let peak = PEAK.with(Cell::get) - BASE.with(Cell::get);
        usize::try_from(peak).unwrap_or(0)
    }
}

#[cfg(test)]
#[global_allocator]
static ALLOCATOR: alloc_probe::Counting = alloc_probe::Counting;

#[cfg(test)]
mod tests {
    use std::fmt::{Display, Write as _};

    use super::*;

    struct Text(String);

    impl Display for Text {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            bounded_display(formatter, |out| write!(out, "{}", self.0))
        }
    }

    #[test]
    fn display_is_cut_on_a_char_boundary() {
        // 2-byte chars with an odd limit would split a char if cut by bytes.
        let text = Text("é".repeat(ERROR_DISPLAY_LIMIT)).to_string();
        assert!(text.ends_with("... (truncated)"));
        assert!(text.len() <= ERROR_DISPLAY_LIMIT + "... (truncated)".len());
        assert!(text.starts_with('é'));
    }

    #[test]
    fn short_display_is_untouched() {
        assert_eq!(Text("detail".into()).to_string(), "detail");
        let exact = "x".repeat(ERROR_DISPLAY_LIMIT);
        assert_eq!(Text(exact.clone()).to_string(), exact);
    }
}
