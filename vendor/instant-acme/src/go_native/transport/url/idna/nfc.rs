// Copyright 2011 The Go Authors. All rights reserved.
// Adapted from selected x/text/unicode/norm NFC; see LICENSE-GO.

//! Whole-string NFC for the IDNA boundary. Uses Go's selected properties,
//! canonical decomposition and composition, including its 30-nonstarter
//! stream-safe segmentation. No newer host/ICU Unicode tables are consulted.

use super::{data, trie};

const FIRST_CCC: usize = 0x2dd5;
const FIRST_LEADING_CCC: usize = 0x4aef;
const FIRST_STARTER_WITH_N_LEAD: usize = 0x4be0;

#[derive(Clone, Copy, Default)]
struct Properties {
    ccc: u8,
    flags: u8,
    n_lead: u8,
    index: usize,
}

impl Properties {
    fn of(ch: char) -> Self {
        let value = trie::nfc(ch);
        if value == 0 {
            return Self::default();
        }
        if value >= 0x8000 {
            let mut info = Self {
                ccc: value as u8,
                flags: (value >> 8) as u8,
                ..Self::default()
            };
            if info.ccc > 0 || info.backwards() {
                info.n_lead = info.flags & 3;
            }
            return info;
        }
        let mut index = usize::from(value);
        let header = data::DECOMPS[index];
        let mut info = Self {
            flags: ((header & 0xe0) >> 2) | 4,
            index,
            ..Self::default()
        };
        if index >= FIRST_CCC {
            let count = match header & 0x1f {
                31 => 33,
                n => usize::from(n),
            };
            index += count + 1;
            let tail = data::DECOMPS[index];
            info.flags |= tail & 3;
            if index >= FIRST_LEADING_CCC {
                info.n_lead = tail & 3;
                if index >= FIRST_STARTER_WITH_N_LEAD {
                    info.flags &= 3;
                    info.index = 0;
                    return info;
                }
                info.ccc = data::DECOMPS[index + 1];
            }
        }
        info
    }

    fn backwards(self) -> bool {
        self.flags & 8 != 0
    }

    fn boundary_before(self) -> bool {
        self.ccc == 0 && !self.backwards()
    }

    fn decomposition(self) -> Option<&'static str> {
        if self.index == 0 {
            return None;
        }
        let count = match data::DECOMPS[self.index] & 0x1f {
            31 => 33,
            n => usize::from(n),
        };
        // These are pinned generated UTF-8 sequences, not untrusted bytes.
        std::str::from_utf8(&data::DECOMPS[self.index + 1..self.index + 1 + count]).ok()
    }
}

#[derive(Clone, Copy)]
struct Rune {
    ch: char,
    info: Properties,
}

#[derive(Default)]
struct Buffer {
    runes: Vec<Rune>,
    output: String,
    nonstarters: u8,
}

impl Buffer {
    fn ordered(&mut self, ch: char, info: Properties) {
        let mut at = self.runes.len();
        if info.ccc > 0 {
            while at > 0 && self.runes[at - 1].info.ccc > info.ccc {
                at -= 1;
            }
        }
        self.runes.insert(at, Rune { ch, info });
    }

    fn assign(&mut self, at: usize, ch: char) {
        // Go assignRune discards the original properties of a combined rune.
        self.runes[at] = Rune {
            ch,
            info: Properties::default(),
        };
    }

    fn combine_hangul(&mut self, mut starter: usize, from: usize, mut kept: usize) {
        for at in from..self.runes.len() {
            let before = self.runes[kept - 1].info.ccc;
            let current = self.runes[at].info.ccc;
            if before == 0 {
                starter = kept - 1;
            }
            if starter != kept - 1 && before >= current {
                self.runes[kept] = self.runes[at];
                kept += 1;
                continue;
            }
            let left = self.runes[starter].ch as u32;
            let right = self.runes[at].ch as u32;
            let combined = if (0x1100..0x1113).contains(&left) && (0x1161..0x1176).contains(&right)
            {
                Some(0xac00 + (left - 0x1100) * 588 + (right - 0x1161) * 28)
            } else if (0xac00..0xd7a4).contains(&left)
                && (0x11a8..0x11c3).contains(&right)
                && (left - 0xac00) % 28 == 0
            {
                Some(left + right - 0x11a7)
            } else {
                None
            };
            if let Some(ch) = combined.and_then(char::from_u32) {
                self.assign(starter, ch);
            } else {
                self.runes[kept] = self.runes[at];
                kept += 1;
            }
        }
        self.runes.truncate(kept);
    }

    fn compose(&mut self) {
        if self.runes.is_empty() {
            return;
        }
        let mut kept = 1;
        let mut starter = 0;
        for at in 1..self.runes.len() {
            // Go isJamoVT recognizes the full U+1100..U+11FF block.
            if ('\u{1100}'..'\u{1200}').contains(&self.runes[at].ch) {
                self.combine_hangul(starter, at, kept);
                return;
            }
            let current = self.runes[at];
            if current.info.backwards() {
                let before = self.runes[kept - 1].info.ccc;
                let mut blocked = false;
                if before == 0 {
                    starter = kept - 1;
                } else {
                    blocked = starter != kept - 1 && before >= current.info.ccc;
                }
                if !blocked {
                    // Match Go's intentionally truncated uint16 pair keys.
                    let key = ((self.runes[starter].ch as u32 & 0xffff) << 16)
                        | (current.ch as u32 & 0xffff);
                    if let Ok(index) = data::RECOMPOSE.binary_search_by_key(&key, |p| p.0) {
                        if let Some(ch) = char::from_u32(data::RECOMPOSE[index].1) {
                            self.assign(starter, ch);
                            continue;
                        }
                    }
                }
            }
            self.runes[kept] = current;
            kept += 1;
        }
        self.runes.truncate(kept);
    }

    fn flush(&mut self) {
        self.compose();
        self.output.extend(self.runes.iter().map(|r| r.ch));
        self.runes.clear();
    }

    fn insert(&mut self, ch: char, info: Properties) {
        let scalar = ch as u32;
        if (0xac00..0xd7a4).contains(&scalar) {
            let syllable = scalar - 0xac00;
            let trailing = syllable % 28;
            self.ordered(
                char::from_u32(0x1100 + syllable / 588).unwrap_or('\u{fffd}'),
                Properties::default(),
            );
            self.ordered(
                char::from_u32(0x1161 + (syllable / 28) % 21).unwrap_or('\u{fffd}'),
                Properties::default(),
            );
            if trailing != 0 {
                self.ordered(
                    char::from_u32(0x11a7 + trailing).unwrap_or('\u{fffd}'),
                    Properties::default(),
                );
            }
        } else if let Some(decomposition) = info.decomposition() {
            for decomposed in decomposition.chars() {
                let info = Properties::of(decomposed);
                if info.boundary_before() && !self.runes.is_empty() {
                    self.flush();
                }
                self.ordered(decomposed, info);
            }
        } else {
            self.ordered(ch, info);
        }
    }
}

pub(super) fn normalize(input: &str) -> String {
    let mut buffer = Buffer {
        runes: Vec::with_capacity(32),
        output: String::with_capacity(input.len()),
        nonstarters: 0,
    };
    for ch in input.chars() {
        let info = Properties::of(ch);
        let next = buffer.nonstarters + info.n_lead;
        if next > 30 {
            // Go emits CGJ and retries the same original rune in a fresh
            // segment; decomposition-internal flushes do not reset this count.
            buffer.nonstarters = 0;
            buffer.ordered('\u{034f}', Properties::default());
            buffer.flush();
        }
        buffer.nonstarters += info.n_lead;
        if info.n_lead == 0 {
            buffer.nonstarters = info.flags & 3;
            if !buffer.runes.is_empty() {
                buffer.flush();
            }
        }
        buffer.insert(ch, info);
    }
    buffer.flush();
    buffer.output
}
