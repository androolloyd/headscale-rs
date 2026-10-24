// Copyright 2009 The Go Authors. All rights reserved.
// Go 1.26.9 io.ReadAll and runtime byte-allocation sizing. See LICENSE-GO.

pub(super) struct ReadAll {
    capacity: usize,
    used: usize,
    next: usize,
}

impl ReadAll {
    pub(super) fn new() -> Self {
        Self {
            capacity: 512,
            used: 0,
            next: 256,
        }
    }
    pub(super) fn maximum(&self) -> usize {
        self.capacity - self.used
    }
    pub(super) fn advance(&mut self, count: usize) -> Option<()> {
        self.used = self.used.checked_add(count)?;
        if self.used > self.capacity {
            return None;
        }
        if self.capacity - self.used < self.capacity / 16 {
            self.capacity = round_bytes(self.next)?;
            self.next = self.next.checked_add(self.next / 2)?;
            self.used = 0;
        }
        Some(())
    }
}

// io.ReadAll allocates each next chunk by append(nil, make([]byte,next)...),
// so its byte capacity is rounded by the selected Go runtime's noscan sizes.
fn round_bytes(size: usize) -> Option<usize> {
    const CLASSES: &[usize] = &[
        8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320,
        352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792,
        2048, 2304, 2688, 3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472,
        9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760, 24576, 27264,
        28672, 32768,
    ];
    if let Some(&class) = CLASSES.iter().find(|&&class| class >= size) {
        return Some(class);
    }
    size.checked_add(8191).map(|size| size & !8191)
}
