//! The pinned util.YesNo prompt shared by upstream admin commands.

use std::io::{self, BufRead, Write};

pub(super) fn confirm_action(prompt: &str) -> bool {
    {
        let mut stderr = io::stderr().lock();
        let _ = write!(stderr, "{prompt} [y/n] ");
        let _ = stderr.flush();
    }
    // fmt.Scanln stores the first token even if additional input makes its
    // final newline check fail. Go intentionally ignores that scan error.
    // Decode invalid input like Go's rune reader rather than failing a UTF-8
    // read_line before an otherwise valid first token can be inspected.
    let mut response = Vec::new();
    let _ = io::stdin().lock().read_until(b'\n', &mut response);
    String::from_utf8_lossy(&response)
        .split_whitespace()
        .next()
        .is_some_and(|answer| {
            ["y", "yes", "sure"]
                .iter()
                .any(|yes| answer.eq_ignore_ascii_case(yes))
        })
}
