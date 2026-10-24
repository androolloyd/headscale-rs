// Copyright (c) 2020 pterm
// Copyright (c) 2016 inhere
// Pinned pterm/gookit escape handling. Original MIT terms and attribution are
// retained in NOTICE-PTERM, LICENSE-PTERM and LICENSE-GOOKIT-COLOR.
// SPDX-License-Identifier: MIT

//! pterm measures the text inside OSC 8 hyperlinks and strips color sequences
//! through gookit/color.ClearCode. Rendering still prints the original bytes.

use std::sync::LazyLock;

use regex::Regex;

use super::runewidth::string_width;

static OSC8: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\x1b\]8;;[^\x07]*?(?:\x07|\x1b\\)(.*?)\x1b\]8;;(?:\x07|\x1b\\)")
        .expect("pinned pterm OSC 8 expression")
});
static COLOR: LazyLock<Regex> = LazyLock::new(|| {
    // Go regexp's \d is ASCII; Rust regex's Unicode \d would be broader.
    Regex::new(r"\x1b\[[0-9;?]+m").expect("pinned gookit color expression")
});

pub(super) fn visible_width(value: &str) -> usize {
    value.split('\n').map(line_width).max().unwrap_or(0)
}

fn line_width(value: &str) -> usize {
    let visible = OSC8.replace_all(value, "$1");
    // ClearCode intentionally returns early without the literal reset suffix.
    if visible.contains("[0m") {
        string_width(COLOR.replace_all(visible.as_ref(), "").as_ref())
    } else {
        string_width(visible.as_ref())
    }
}
