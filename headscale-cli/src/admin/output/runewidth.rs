// Copyright (c) 2016 Yasuhiro Matsumoto
// Copyright (c) 2020 Matt Sherman
// SPDX-License-Identifier: MIT
// See NOTICE-PTERM, LICENSE-GO-RUNEWIDTH and LICENSE-UAX29.

//! The default go-runewidth v0.0.24 condition, with uax29 v2.7.0 clusters.
//! Keep the first-positive-rune rule: it deliberately differs from measuring
//! the rendered glyph for the whole cluster (for example, emoji selectors).

use std::sync::LazyLock;

use headscale_api_acl::go_unicode::to_lowercase;
use regex::Regex;

mod tables;

use tables::{AMBIGUOUS, COMBINING, DOUBLEWIDTH, GRAPHEME_PROPERTIES, NONPRINT};

static EAST_ASIAN: LazyLock<bool> = LazyLock::new(|| {
    let override_value = env("RUNEWIDTH_EASTASIAN");
    if override_value.is_empty() {
        locale_is_east_asian()
    } else {
        override_value == "1"
    }
});

fn env(name: &str) -> String {
    std::env::var_os(name)
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(unix)]
fn locale_is_east_asian() -> bool {
    static LOCALE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[a-z][a-z][a-z]?(?:_[A-Z][A-Z])?\.(.+)")
            .expect("pinned go-runewidth POSIX locale expression")
    });
    let locale = ["LC_ALL", "LC_CTYPE", "LANG"]
        .into_iter()
        .map(env)
        .find(|value| !value.is_empty())
        .unwrap_or_default();
    if matches!(locale.as_str(), "POSIX" | "C")
        || locale.starts_with("C.")
        || locale.starts_with("C-")
    {
        return false;
    }
    let captures = LOCALE.captures(&locale);
    let charset = to_lowercase(
        captures
            .as_ref()
            .and_then(|captures| captures.get(1))
            .map_or(locale.as_str(), |capture| capture.as_str()),
    );
    if charset.ends_with("@cjk_narrow") {
        return false;
    }
    let charset = charset.split('@').next().unwrap_or_default();
    let multibyte = matches!(
        charset,
        "utf-8"
            | "utf8"
            | "jis"
            | "eucjp"
            | "euckr"
            | "euccn"
            | "sjis"
            | "cp932"
            | "cp51932"
            | "cp936"
            | "cp949"
            | "cp950"
            | "big5"
            | "gbk"
            | "gb2312"
    );
    multibyte
        && (!charset.starts_with('u')
            || locale.starts_with("ja")
            || locale.starts_with("ko")
            || locale.starts_with("zh"))
}

#[cfg(not(unix))]
fn locale_is_east_asian() -> bool {
    // The operator CLI currently requires UnixStream. Non-POSIX console code
    // page discovery is outside this port; an explicit override still works.
    false
}

fn contains(table: &[(u32, u32)], rune: u32) -> bool {
    let index = table.partition_point(|&(_, end)| end < rune);
    table.get(index).is_some_and(|&(start, _)| start <= rune)
}

fn rune_width(rune: char, east_asian: bool) -> usize {
    let rune = rune as u32;
    if !east_asian {
        if rune < 0x20 || (0x7F..=0x9F).contains(&rune) || rune == 0xAD {
            return 0;
        }
        if rune < 0x300 {
            return 1;
        }
    }
    // Go's merged width table gives zero-width intervals priority over wide
    // intervals, in both paths. The default StrictEmojiNeutral flag is true.
    if contains(COMBINING, rune) || contains(NONPRINT, rune) {
        0
    } else if contains(DOUBLEWIDTH, rune) || (east_asian && contains(AMBIGUOUS, rune)) {
        2
    } else {
        1
    }
}

pub(super) fn string_width(value: &str) -> usize {
    if value.len() == 1 {
        let byte = value.as_bytes()[0];
        return usize::from(byte >= 0x20 && byte != 0x7F);
    }
    let east_asian = *EAST_ASIAN;
    if let Some(rune) = value.chars().next()
        && rune.len_utf8() == value.len()
    {
        return rune_width(rune, east_asian);
    }
    if value.is_ascii() {
        return value
            .bytes()
            .filter(|&byte| byte >= 0x20 && byte != 0x7F)
            .count();
    }
    let mut remaining = value;
    let mut width = 0;
    while !remaining.is_empty() {
        let next = next_grapheme_len(remaining);
        width += remaining[..next]
            .chars()
            .map(|rune| rune_width(rune, east_asian))
            .find(|&width| width > 0)
            .unwrap_or(0);
        remaining = &remaining[next..];
    }
    width
}

const CR: u32 = 1 << 0;
const CONTROL: u32 = 1 << 1;
const EXTEND: u32 = 1 << 2;
const EXTENDED_PICTOGRAPHIC: u32 = 1 << 3;
const INCB_CONSONANT: u32 = 1 << 4;
const INCB_EXTEND: u32 = 1 << 5;
const INCB_LINKER: u32 = 1 << 6;
const L: u32 = 1 << 7;
const LF: u32 = 1 << 8;
const LV: u32 = 1 << 9;
const LVT: u32 = 1 << 10;
const PREPEND: u32 = 1 << 11;
const REGIONAL_INDICATOR: u32 = 1 << 12;
const SPACING_MARK: u32 = 1 << 13;
const T: u32 = 1 << 14;
const V: u32 = 1 << 15;
const ZWJ: u32 = 1 << 16;

fn property(rune: char) -> u32 {
    let rune = rune as u32;
    let index = GRAPHEME_PROPERTIES.partition_point(|&(_, end, _)| end < rune);
    GRAPHEME_PROPERTIES
        .get(index)
        .filter(|&&(start, _, _)| start <= rune)
        .map_or(0, |&(_, _, value)| value)
}

fn is(value: u32, categories: u32) -> bool {
    value & categories != 0
}

fn next_grapheme_len(value: &str) -> usize {
    let bytes = value.as_bytes();
    // uax29 Iterator.Next's ASCII hot path, with ANSI handling left disabled.
    if bytes[0] < 0x80 && bytes[0] != b'\r' && (bytes.len() == 1 || bytes[1] < 0x80) {
        return 1;
    }
    let mut runes = value.char_indices();
    let (_, first) = runes.next().expect("nonempty grapheme input");
    let mut current = property(first);
    let mut last_ex_ignore = 0;
    let mut last_last_ex_ignore = 0;
    let mut regional_indicator_count = 0;
    let mut incb = 0;
    for (position, rune) in runes {
        let last = current;
        if !is(last, EXTEND) {
            last_last_ex_ignore = last_ex_ignore;
            last_ex_ignore = last;
        }
        if is(last, INCB_CONSONANT | INCB_LINKER | INCB_EXTEND) {
            if is(last, INCB_CONSONANT) {
                if incb != 2 {
                    incb = 1;
                }
            } else if is(last, INCB_LINKER) && incb >= 1 {
                incb = 2;
            }
        } else {
            incb = 0;
        }
        current = property(rune);
        if current | last == 0 {
            return position;
        }
        // GB3, followed by GB4/GB5 (control breaks precede the other rules).
        if is(current, LF) && is(last, CR) {
            continue;
        }
        if is(current | last, CONTROL | CR | LF) {
            return position;
        }
        // GB6, GB7, GB8, GB9, GB9a, GB9b.
        if (is(current, L | V | LV | LVT) && is(last, L))
            || (is(current, V | T) && is(last, LV | V))
            || (is(current, T) && is(last, LVT | T))
            || is(current, EXTEND | ZWJ | SPACING_MARK)
            || is(last, PREPEND)
        {
            continue;
        }
        // GB9c resets at the newly admitted Indic consonant.
        if incb == 2 && is(current, INCB_CONSONANT) {
            incb = 1;
            continue;
        }
        // GB11 ignores Extend, but not ZWJ, when looking back.
        if is(current, EXTENDED_PICTOGRAPHIC)
            && is(last, ZWJ)
            && is(last_last_ex_ignore, EXTENDED_PICTOGRAPHIC)
        {
            continue;
        }
        // GB12/GB13 pair regional indicators within this cluster.
        if is(current & last, REGIONAL_INDICATOR) {
            regional_indicator_count += 1;
            if regional_indicator_count % 2 == 1 {
                continue;
            }
        }
        return position;
    }
    value.len()
}
