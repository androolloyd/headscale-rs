//! OpaqueString profile from golang.org/x/text v0.38.0 secure/precis.
//! Copyright 2015, 2016 The Go Authors. All rights reserved.
//! BSD-3-Clause license: LICENSE-GO-TEXT in this vendor directory.

use std::borrow::Cow;
use unicode_normalization::UnicodeNormalization as _;

mod tables;

const JAPANESE: u16 = 1;
const ARABIC: u16 = 2;
const EXT_ARABIC: u16 = 4;
const JOIN_START: u16 = 8;
const JOIN_MID: u16 = 16;
const JOIN_END: u16 = 32;
const VIRAMA: u16 = 64;
const LATIN_L: u16 = 128;
const GREEK: u16 = 256;
const HEBREW: u16 = 512;
const MUST_HAVE_JAPANESE: u16 = 1024;
const PERMANENT: u16 = JAPANESE | ARABIC | EXT_ARABIC | MUST_HAVE_JAPANESE;

fn valid(input: &str) -> bool {
    let mut before = 0_u16;
    let mut term = 0_u16;
    let mut accept = 0_u16;
    for character in input.chars() {
        let entry = tables::entry(character);
        let category = entry & 0x3f;
        let mut keep = PERMANENT;
        let mut set = 0;
        let (next_term, next_accept) = match category {
            13 => (JOIN_END, JOIN_MID | JOIN_END),
            15 => (LATIN_L, LATIN_L),
            16 => (GREEK, GREEK),
            _ => (0, 0),
        };
        let mut lookahead = false;
        if entry < 0x80 {
            match category {
                13 if before & VIRAMA != 0 => {}
                13 if before & JOIN_START != 0 => lookahead = true,
                14 if before & VIRAMA != 0 => {}
                15 if before & LATIN_L != 0 => lookahead = true,
                16 => lookahead = true,
                17 if before & HEBREW != 0 => {}
                19 if before & EXT_ARABIC == 0 => {}
                20 if before & ARABIC == 0 => {}
                _ => return false,
            }
        }
        match category {
            1 => set = JOIN_START,
            2 => set = JOIN_START | JOIN_END,
            3 => {
                keep |= JOIN_START;
                set = JOIN_MID;
            }
            4 => set = JOIN_END,
            5 => set = VIRAMA,
            6 => set = VIRAMA | JOIN_MID,
            7 => set = LATIN_L,
            8 | 16 => set = GREEK,
            9 => set = GREEK | JOIN_MID,
            10 | 17 => set = HEBREW,
            11 => set = HEBREW | JOIN_MID,
            12 => set = JAPANESE,
            18 => set = MUST_HAVE_JAPANESE,
            19 => set = ARABIC,
            20 => set = EXT_ARABIC,
            _ => {}
        }
        before = (before & keep) | set;
        if term != 0 {
            if before & term != 0 {
                term = 0;
                accept = 0;
            } else if before & accept == 0 {
                return false;
            }
        }
        if lookahead {
            if term != 0 {
                return false;
            }
            term = next_term;
            accept = next_accept;
        }
    }
    let required = before >> 10;
    before & required == required && term == 0
}

pub(super) fn password(input: &str) -> Cow<'_, str> {
    // Go's Unicode-15 checker rejects these even when the newer Rust NFC
    // tables know how to normalize them. pgx falls back to the original bytes.
    if input.is_empty()
        || input
            .chars()
            .any(|character| tables::entry(character) & 0xc0 == 0)
    {
        return Cow::Borrowed(input);
    }
    let normalized: String = input
        .chars()
        .map(|character| match character {
            '\u{20}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}' => ' ',
            _ => character,
        })
        .stream_safe()
        .nfc()
        .collect();
    if normalized == input || !valid(&normalized) {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(normalized)
    }
}
