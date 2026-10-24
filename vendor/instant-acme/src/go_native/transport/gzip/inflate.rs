// Copyright 2009, 2016 The Go Authors. All rights reserved.
// Source-derived from Go 1.26.9 compress/flate/{inflate,dict_decoder}.go;
// see LICENSE-GO and LICENSE-GO-NOTICE.

//! Incremental raw DEFLATE. Huffman lookups follow the selected Go decoder's
//! minimum-bit reads, including the EOB minimum, so no gzip trailer byte is
//! consumed speculatively. A persistent 32 KiB dictionary also retains output
//! until Go's dictionary-flush boundaries, input failure or final block.

const WINDOW: usize = 32 * 1024;
const CHUNK_BITS: usize = 9;
const CHUNKS: usize = 1 << CHUNK_BITS;
const CODE_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Status {
    NeedInput,
    /// Pending output, or a completed dictionary flush. The caller may resume
    /// with the unconsumed input even when its previous output buffer was large.
    OutputFull,
    Done,
    Corrupt(u64),
    UnexpectedEof,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Step {
    pub(super) consumed: usize,
    pub(super) produced: usize,
    pub(super) status: Status,
}

#[derive(Default)]
struct Huffman {
    min: usize,
    chunks: Vec<u32>,
    links: Vec<Vec<u32>>,
    link_mask: usize,
}

impl Huffman {
    fn init(&mut self, lengths: &[u8]) -> bool {
        self.min = 0;
        self.chunks.clear();
        self.chunks.resize(CHUNKS, 0);
        self.links.clear();
        self.link_mask = 0;
        let mut count = [0usize; 16];
        let mut maximum = 0;
        for &length in lengths {
            let length = usize::from(length);
            // All callers supply three-bit code lengths or decoded symbols
            // 0..15. Keep this private constructor safe if a caller changes.
            if length >= count.len() {
                return false;
            }
            if length != 0 {
                count[length] += 1;
                if self.min == 0 || length < self.min {
                    self.min = length;
                }
                maximum = maximum.max(length);
            }
        }
        // Empty trees are accepted on construction and fail when used.
        if maximum == 0 {
            return true;
        }
        let mut code = 0;
        let mut next = [0usize; 16];
        for length in self.min..=maximum {
            code <<= 1;
            next[length] = code;
            code += count[length];
        }
        if code != 1usize << maximum && !(code == 1 && maximum == 1) {
            return false;
        }
        if maximum > CHUNK_BITS {
            let width = 1usize << (maximum - CHUNK_BITS);
            self.link_mask = width - 1;
            let first_link = next[CHUNK_BITS + 1] >> 1;
            self.links
                .resize_with(CHUNKS - first_link, || vec![0; width]);
            for prefix in first_link..CHUNKS {
                let reverse = (prefix as u16).reverse_bits() >> (16 - CHUNK_BITS);
                self.chunks[usize::from(reverse)] =
                    (((prefix - first_link) << 4) | (CHUNK_BITS + 1)) as u32;
            }
        }
        for (symbol, &length) in lengths.iter().enumerate() {
            let length = usize::from(length);
            if length == 0 {
                continue;
            }
            let code = next[length];
            next[length] += 1;
            let chunk = ((symbol << 4) | length) as u32;
            let reverse = usize::from((code as u16).reverse_bits() >> (16 - length));
            if length <= CHUNK_BITS {
                for at in (reverse..CHUNKS).step_by(1 << length) {
                    self.chunks[at] = chunk;
                }
            } else {
                let link = (self.chunks[reverse & (CHUNKS - 1)] >> 4) as usize;
                for at in ((reverse >> CHUNK_BITS)..self.links[link].len())
                    .step_by(1 << (length - CHUNK_BITS))
                {
                    self.links[link][at] = chunk;
                }
            }
        }
        true
    }

    fn fixed() -> &'static Self {
        static FIXED: std::sync::OnceLock<Huffman> = std::sync::OnceLock::new();
        FIXED.get_or_init(|| {
            let mut lengths = [0; 288];
            lengths[..144].fill(8);
            lengths[144..256].fill(9);
            lengths[256..280].fill(7);
            lengths[280..].fill(8);
            let mut table = Self::default();
            // This literal construction is complete by RFC 1951 section 3.2.6.
            let _ = table.init(&lengths);
            table
        })
    }

    fn symbol(&self, bits: &mut Bits, input: &mut Input<'_>) -> Symbol {
        let mut wanted = self.min;
        loop {
            if !bits.ensure(wanted, input) {
                return Symbol::NeedInput;
            }
            let mut chunk = self.chunks[(bits.value as usize) & (CHUNKS - 1)];
            wanted = (chunk & 15) as usize;
            if wanted > CHUNK_BITS {
                chunk = self.links[(chunk >> 4) as usize]
                    [((bits.value >> CHUNK_BITS) as usize) & self.link_mask];
                wanted = (chunk & 15) as usize;
            }
            if wanted <= bits.count {
                if wanted == 0 {
                    return Symbol::Corrupt;
                }
                bits.take(wanted);
                return Symbol::Value((chunk >> 4) as usize);
            }
        }
    }
}

enum Symbol {
    NeedInput,
    Corrupt,
    Value(usize),
}

#[derive(Default)]
struct Bits {
    value: u32,
    count: usize,
    offset: u64,
}

impl Bits {
    fn ensure(&mut self, count: usize, input: &mut Input<'_>) -> bool {
        while self.count < count {
            let Some(&byte) = input.bytes.get(input.at) else {
                return false;
            };
            input.at += 1;
            self.offset = self.offset.wrapping_add(1);
            self.value |= u32::from(byte) << self.count;
            self.count += 8;
        }
        true
    }
    fn take(&mut self, count: usize) -> usize {
        let value = self.value & ((1u32 << count) - 1);
        self.value >>= count;
        self.count -= count;
        value as usize
    }
}

struct Input<'a> {
    bytes: &'a [u8],
    at: usize,
}

#[derive(Clone, Copy)]
enum Phase {
    Block,
    StoredHeader {
        read: usize,
        bytes: [u8; 4],
    },
    StoredCopy(usize),
    DynamicHeader,
    CodeLengths,
    Lengths,
    Repeat {
        base: usize,
        extra: usize,
        value: u8,
    },
    Literal,
    LengthExtra {
        base: usize,
        extra: usize,
    },
    Distance {
        length: usize,
    },
    DistanceExtra {
        length: usize,
        code: usize,
    },
    Copy {
        remaining: usize,
        distance: usize,
    },
    Terminal(Status),
}

pub(super) struct Inflater {
    bits: Bits,
    phase: Phase,
    final_block: bool,
    fixed: bool,
    literal: Huffman,
    distance: Huffman,
    code: Huffman,
    lengths: [u8; 316],
    code_lengths: [u8; 19],
    nlit: usize,
    ndist: usize,
    ncode: usize,
    index: usize,
    history: Vec<u8>,
    written: usize,
    read: usize,
    full: bool,
    pending_at: usize,
    pending_end: usize,
    input_ended: bool,
}

impl Inflater {
    /// Demand of the next Go flate reader call when buffered input is empty.
    /// Huffman paths use ReadByte; stored blocks read into the dictionary span.
    pub(super) fn input_read_size(&self) -> usize {
        match self.phase {
            Phase::StoredCopy(remaining) => remaining.min(WINDOW - self.written).max(1),
            _ => 1,
        }
    }

    pub(super) fn new() -> Self {
        // The fixed table is shared across readers/blocks, as Go fixedOnce is.
        let _ = Huffman::fixed();
        Self {
            bits: Bits::default(),
            phase: Phase::Block,
            final_block: false,
            fixed: false,
            literal: Huffman::default(),
            distance: Huffman::default(),
            code: Huffman::default(),
            lengths: [0; 316],
            code_lengths: [0; 19],
            nlit: 0,
            ndist: 0,
            ncode: 0,
            index: 0,
            history: vec![0; WINDOW],
            written: 0,
            read: 0,
            full: false,
            pending_at: 0,
            pending_end: 0,
            input_ended: false,
        }
    }

    /// Signal the underlying reader's EOF. Any dictionary bytes not yet
    /// returned are delivered before/alongside UnexpectedEof on the next read.
    pub(super) fn finish_input(&mut self) {
        self.input_ended = true;
    }

    fn flush(&mut self) {
        self.pending_at = self.read;
        self.pending_end = self.written;
        self.read = self.written;
        if self.written == WINDOW {
            self.written = 0;
            self.read = 0;
            self.full = true;
        }
    }

    fn terminal(&mut self, status: Status) {
        self.phase = Phase::Terminal(status);
        // An empty stored block already flushed before finishBlock. Preserve
        // that pending span instead of replacing it with an empty second one.
        if self.pending_at == self.pending_end {
            self.flush();
        }
    }

    fn finish_block(&mut self) {
        if self.final_block {
            self.terminal(Status::Done);
        } else {
            self.phase = Phase::Block;
        }
    }

    fn write_byte(&mut self, byte: u8) {
        self.history[self.written] = byte;
        self.written += 1;
    }

    fn need_input(&mut self) -> Option<Status> {
        if self.input_ended {
            self.terminal(Status::UnexpectedEof);
            None
        } else {
            Some(Status::NeedInput)
        }
    }

    /// Decode without borrowing caller memory across calls. consumed excludes
    /// the gzip trailer; produced never exceeds output.len(). Terminal status
    /// may accompany the last output bytes and remains sticky thereafter.
    pub(super) fn read(&mut self, input: &[u8], output: &mut [u8]) -> Step {
        let mut input = Input {
            bytes: input,
            at: 0,
        };
        let mut produced = 0;
        let status = loop {
            if self.pending_at != self.pending_end {
                let count = (self.pending_end - self.pending_at).min(output.len());
                output[..count]
                    .copy_from_slice(&self.history[self.pending_at..self.pending_at + count]);
                self.pending_at += count;
                produced = count;
                break if self.pending_at != self.pending_end {
                    Status::OutputFull
                } else {
                    match self.phase {
                        Phase::Terminal(status) => status,
                        _ => Status::OutputFull,
                    }
                };
            }
            if let Phase::Terminal(status) = self.phase {
                break status;
            }
            if output.is_empty() {
                break Status::OutputFull;
            }
            match self.phase {
                Phase::Block => {
                    if !self.bits.ensure(3, &mut input) {
                        if let Some(status) = self.need_input() {
                            break status;
                        }
                        continue;
                    }
                    self.final_block = self.bits.take(1) == 1;
                    match self.bits.take(2) {
                        0 => {
                            self.bits.value = 0;
                            self.bits.count = 0;
                            self.phase = Phase::StoredHeader {
                                read: 0,
                                bytes: [0; 4],
                            };
                        }
                        1 => {
                            self.fixed = true;
                            self.phase = Phase::Literal;
                        }
                        2 => self.phase = Phase::DynamicHeader,
                        _ => self.terminal(Status::Corrupt(self.bits.offset)),
                    }
                }
                Phase::StoredHeader {
                    mut read,
                    mut bytes,
                } => {
                    while read < bytes.len() && input.at < input.bytes.len() {
                        bytes[read] = input.bytes[input.at];
                        input.at += 1;
                        self.bits.offset = self.bits.offset.wrapping_add(1);
                        read += 1;
                    }
                    self.phase = Phase::StoredHeader { read, bytes };
                    if read != 4 {
                        if let Some(status) = self.need_input() {
                            break status;
                        }
                        continue;
                    }
                    let length = u16::from_le_bytes([bytes[0], bytes[1]]);
                    let complement = u16::from_le_bytes([bytes[2], bytes[3]]);
                    if complement != !length {
                        self.terminal(Status::Corrupt(self.bits.offset));
                    } else if length == 0 {
                        self.flush();
                        self.finish_block();
                    } else {
                        self.phase = Phase::StoredCopy(usize::from(length));
                    }
                }
                Phase::StoredCopy(mut remaining) => {
                    let count = remaining
                        .min(WINDOW - self.written)
                        .min(input.bytes.len() - input.at);
                    self.history[self.written..self.written + count]
                        .copy_from_slice(&input.bytes[input.at..input.at + count]);
                    self.written += count;
                    input.at += count;
                    self.bits.offset = self.bits.offset.wrapping_add(count as u64);
                    remaining -= count;
                    self.phase = Phase::StoredCopy(remaining);
                    if remaining == 0 {
                        self.finish_block();
                    }
                    if self.written == WINDOW {
                        self.flush();
                    }
                    if remaining != 0
                        && self.pending_at == self.pending_end
                        && input.at == input.bytes.len()
                    {
                        if let Some(status) = self.need_input() {
                            break status;
                        }
                    }
                }
                Phase::DynamicHeader => {
                    if !self.bits.ensure(14, &mut input) {
                        if let Some(status) = self.need_input() {
                            break status;
                        }
                        continue;
                    }
                    self.nlit = (self.bits.value as usize & 31) + 257;
                    self.ndist = ((self.bits.value >> 5) as usize & 31) + 1;
                    if self.nlit > 286 || self.ndist > 30 {
                        self.terminal(Status::Corrupt(self.bits.offset));
                        continue;
                    }
                    self.bits.take(10);
                    self.ncode = self.bits.take(4) + 4;
                    self.code_lengths.fill(0);
                    self.index = 0;
                    self.phase = Phase::CodeLengths;
                }
                Phase::CodeLengths => {
                    if self.index == self.ncode {
                        if !self.code.init(&self.code_lengths) {
                            self.terminal(Status::Corrupt(self.bits.offset));
                        } else {
                            self.index = 0;
                            self.phase = Phase::Lengths;
                        }
                        continue;
                    }
                    if !self.bits.ensure(3, &mut input) {
                        if let Some(status) = self.need_input() {
                            break status;
                        }
                        continue;
                    }
                    self.code_lengths[CODE_ORDER[self.index]] = self.bits.take(3) as u8;
                    self.index += 1;
                }
                Phase::Lengths => {
                    if self.index == self.nlit + self.ndist {
                        if !self.literal.init(&self.lengths[..self.nlit])
                            || !self
                                .distance
                                .init(&self.lengths[self.nlit..self.nlit + self.ndist])
                        {
                            self.terminal(Status::Corrupt(self.bits.offset));
                        } else {
                            self.literal.min = self.literal.min.max(usize::from(self.lengths[256]));
                            self.fixed = false;
                            self.phase = Phase::Literal;
                        }
                        continue;
                    }
                    let symbol = match self.code.symbol(&mut self.bits, &mut input) {
                        Symbol::NeedInput => {
                            if let Some(status) = self.need_input() {
                                break status;
                            }
                            continue;
                        }
                        Symbol::Corrupt => {
                            self.terminal(Status::Corrupt(self.bits.offset));
                            continue;
                        }
                        Symbol::Value(symbol) => symbol,
                    };
                    match symbol {
                        0..=15 => {
                            self.lengths[self.index] = symbol as u8;
                            self.index += 1;
                        }
                        16 if self.index != 0 => {
                            self.phase = Phase::Repeat {
                                base: 3,
                                extra: 2,
                                value: self.lengths[self.index - 1],
                            }
                        }
                        17 => {
                            self.phase = Phase::Repeat {
                                base: 3,
                                extra: 3,
                                value: 0,
                            }
                        }
                        18 => {
                            self.phase = Phase::Repeat {
                                base: 11,
                                extra: 7,
                                value: 0,
                            }
                        }
                        _ => self.terminal(Status::Corrupt(self.bits.offset)),
                    }
                }
                Phase::Repeat { base, extra, value } => {
                    if !self.bits.ensure(extra, &mut input) {
                        if let Some(status) = self.need_input() {
                            break status;
                        }
                        continue;
                    }
                    let count = base + self.bits.take(extra);
                    if self.index + count > self.nlit + self.ndist {
                        self.terminal(Status::Corrupt(self.bits.offset));
                    } else {
                        self.lengths[self.index..self.index + count].fill(value);
                        self.index += count;
                        self.phase = Phase::Lengths;
                    }
                }
                Phase::Literal => {
                    let literal = if self.fixed {
                        Huffman::fixed()
                    } else {
                        &self.literal
                    };
                    let symbol = match literal.symbol(&mut self.bits, &mut input) {
                        Symbol::NeedInput => {
                            if let Some(status) = self.need_input() {
                                break status;
                            }
                            continue;
                        }
                        Symbol::Corrupt => {
                            self.terminal(Status::Corrupt(self.bits.offset));
                            continue;
                        }
                        Symbol::Value(symbol) => symbol,
                    };
                    match symbol {
                        0..=255 => {
                            self.write_byte(symbol as u8);
                            if self.written == WINDOW {
                                self.flush();
                            }
                        }
                        256 => self.finish_block(),
                        257..=285 => {
                            let (base, extra) = match symbol {
                                257..=264 => (symbol - 254, 0),
                                265..=268 => (symbol * 2 - 519, 1),
                                269..=272 => (symbol * 4 - 1057, 2),
                                273..=276 => (symbol * 8 - 2149, 3),
                                277..=280 => (symbol * 16 - 4365, 4),
                                281..=284 => (symbol * 32 - 8861, 5),
                                _ => (258, 0),
                            };
                            self.phase = Phase::LengthExtra { base, extra };
                        }
                        _ => self.terminal(Status::Corrupt(self.bits.offset)),
                    }
                }
                Phase::LengthExtra { base, extra } => {
                    if !self.bits.ensure(extra, &mut input) {
                        if let Some(status) = self.need_input() {
                            break status;
                        }
                        continue;
                    }
                    self.phase = Phase::Distance {
                        length: base + self.bits.take(extra),
                    };
                }
                Phase::Distance { length } => {
                    let code = if self.fixed {
                        if !self.bits.ensure(5, &mut input) {
                            if let Some(status) = self.need_input() {
                                break status;
                            }
                            continue;
                        }
                        (self.bits.take(5) as u8).reverse_bits() as usize >> 3
                    } else {
                        match self.distance.symbol(&mut self.bits, &mut input) {
                            Symbol::NeedInput => {
                                if let Some(status) = self.need_input() {
                                    break status;
                                }
                                continue;
                            }
                            Symbol::Corrupt => {
                                self.terminal(Status::Corrupt(self.bits.offset));
                                continue;
                            }
                            Symbol::Value(symbol) => symbol,
                        }
                    };
                    if code >= 30 {
                        self.terminal(Status::Corrupt(self.bits.offset));
                    } else {
                        self.phase = Phase::DistanceExtra { length, code };
                    }
                }
                Phase::DistanceExtra { length, code } => {
                    let extra = if code < 4 { 0 } else { (code - 2) >> 1 };
                    if !self.bits.ensure(extra, &mut input) {
                        if let Some(status) = self.need_input() {
                            break status;
                        }
                        continue;
                    }
                    let distance = if code < 4 {
                        code + 1
                    } else {
                        (1 << (extra + 1)) + 1 + ((code & 1) << extra) + self.bits.take(extra)
                    };
                    let history = if self.full { WINDOW } else { self.written };
                    if distance > history {
                        self.terminal(Status::Corrupt(self.bits.offset));
                    } else {
                        self.phase = Phase::Copy {
                            remaining: length,
                            distance,
                        };
                    }
                }
                Phase::Copy {
                    mut remaining,
                    distance,
                } => {
                    let count = remaining.min(WINDOW - self.written);
                    for _ in 0..count {
                        let source = (self.written + WINDOW - distance) % WINDOW;
                        self.write_byte(self.history[source]);
                    }
                    remaining -= count;
                    self.phase = if remaining == 0 {
                        Phase::Literal
                    } else {
                        Phase::Copy {
                            remaining,
                            distance,
                        }
                    };
                    if self.written == WINDOW {
                        self.flush();
                    }
                }
                Phase::Terminal(_) => unreachable!("terminal handled above"),
            }
        };
        Step {
            consumed: input.at,
            produced,
            status,
        }
    }
}
