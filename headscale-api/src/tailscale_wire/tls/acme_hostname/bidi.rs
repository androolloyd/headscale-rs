// Copyright 2016 The Go Authors. All rights reserved.
// Adapted from x/text/secure/bidirule; see LICENSE-GO-STDLIB.

use super::trie;

const L: u16 = 1;
const R: u16 = 1 << 1;
const EN: u16 = 1 << 2;
const ES: u16 = 1 << 3;
const ET: u16 = 1 << 4;
const AN: u16 = 1 << 5;
const CS: u16 = 1 << 6;
const ON: u16 = 1 << 10;
const BN: u16 = 1 << 11;
const NSM: u16 = 1 << 12;
const AL: u16 = 1 << 13;

// Initial, LTR, LTRFinal, RTL, RTLFinal, Invalid. Ordered transitions match
// Go's ruleTransition table, including invalid-state behavior before RTL is seen.
const TRANSITIONS: [[(usize, u16); 2]; 6] = [
    [(2, L), (4, R | AL)],
    [(2, L | EN), (1, ES | CS | ET | ON | BN | NSM)],
    [(2, L | EN | NSM), (1, ES | CS | ET | ON | BN)],
    [(4, R | AL | EN | AN), (3, ES | CS | ET | ON | BN | NSM)],
    [(4, R | AL | EN | AN | NSM), (3, ES | CS | ET | ON | BN)],
    [(5, 0), (5, 0)],
];

pub(super) fn is_rtl(ch: char) -> bool {
    matches!(trie::bidi(ch), 1 | 5 | 13)
}

pub(super) fn valid(label: &str) -> bool {
    let mut state = 0;
    let mut seen = 0_u16;
    for ch in label.chars() {
        let class = (1_u32 << trie::bidi(ch)) as u16;
        seen |= class;
        if seen & (EN | AN) == EN | AN {
            return false;
        }
        let transitions = TRANSITIONS[state];
        if transitions[0].1 & class != 0 {
            state = transitions[0].0;
        } else if transitions[1].1 & class != 0 {
            state = transitions[1].0;
        } else {
            state = 5;
            if seen & (R | AL | AN) != 0 {
                return false;
            }
        }
    }
    matches!(state, 0 | 2 | 4)
}
