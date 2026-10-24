// Copyright 2009, 2011, 2022 The Go Authors. All rights reserved.
// Go 1.26.9 time/zoneinfo{,_unix,_read,_goroot}.go; see LICENSE-GO.

//! Private Unix Go Local snapshot. Environment and files are consulted once,
//! on the first non-UTC RFC850 zone. Go's binary may initialize Local earlier.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::OnceLock,
};

mod tzset;

static LOCAL: OnceLock<Location> = OnceLock::new();
const SOURCES: &[&str] = &[
    "/usr/share/zoneinfo/",
    "/usr/share/lib/zoneinfo/",
    "/usr/lib/locale/TZ/",
    "/etc/zoneinfo",
];
const ARCHIVE: &[u8] = include_bytes!("zoneinfo.zip");

struct Zone {
    name: Vec<u8>,
    offset: i32,
    dst: bool,
}

struct Location {
    zones: Vec<Zone>,
    transitions: Vec<(i64, usize)>,
    extension: Vec<u8>,
}

impl Location {
    fn utc() -> Self {
        Self {
            zones: Vec::new(),
            transitions: Vec::new(),
            extension: Vec::new(),
        }
    }

    fn lookup(&self, seconds: i64) -> (&[u8], i32) {
        if self.zones.is_empty() {
            return (b"UTC", 0);
        }
        if self.transitions.is_empty() || seconds < self.transitions[0].0 {
            let first = if !self.transitions.iter().any(|transition| transition.1 == 0) {
                0
            } else if self.zones[self.transitions[0].1].dst {
                (0..self.transitions[0].1)
                    .rev()
                    .find(|index| !self.zones[*index].dst)
                    .or_else(|| self.zones.iter().position(|zone| !zone.dst))
                    .unwrap_or(0)
            } else {
                self.zones.iter().position(|zone| !zone.dst).unwrap_or(0)
            };
            let zone = &self.zones[first];
            return (&zone.name, zone.offset);
        }
        // Match Go's largest-transition<=seconds binary search, including its
        // behavior on malformed unsorted tables; do not sort imported data.
        let (mut lo, mut hi) = (0, self.transitions.len());
        while hi - lo > 1 {
            let middle = (lo + hi) / 2;
            if seconds < self.transitions[middle].0 {
                hi = middle;
            } else {
                lo = middle;
            }
        }
        if lo + 1 == self.transitions.len() {
            if let Some(result) = tzset::lookup(&self.extension, seconds) {
                return result;
            }
        }
        let zone = &self.zones[self.transitions[lo].1];
        (&zone.name, zone.offset)
    }
}

pub(super) fn lookup_name(name: &[u8], wall_seconds: i64) -> Option<i32> {
    let location = LOCAL.get_or_init(load);
    for zone in &location.zones {
        if zone.name == name {
            let (actual, offset) = location.lookup(wall_seconds - i64::from(zone.offset));
            if actual == zone.name {
                return Some(offset);
            }
        }
    }
    location
        .zones
        .iter()
        .find(|zone| zone.name == name)
        .map(|zone| zone.offset)
}

fn os_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

fn path_from_bytes(value: Vec<u8>) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(value).into()
    }
    #[cfg(not(unix))]
    {
        String::from_utf8_lossy(&value).into_owned().into()
    }
}

fn load() -> Location {
    match std::env::var_os("TZ") {
        None => load_location(b"localtime", &["/etc"]).unwrap_or_else(Location::utc),
        Some(value) => {
            let raw = os_bytes(&value);
            let name = raw.strip_prefix(b":").unwrap_or(&raw);
            if name.is_empty() || name == b"UTC" {
                return Location::utc();
            }
            if name.starts_with(b"/") {
                load_location(name, &[""]).unwrap_or_else(Location::utc)
            } else {
                load_location(name, SOURCES).unwrap_or_else(Location::utc)
            }
        }
    }
}

fn load_location(name: &[u8], sources: &[&str]) -> Option<Location> {
    for source in sources {
        // Concatenate like Go, preserving absolute-name handling and dot
        // components; Path::join would discard the supplied directory.
        let mut path = source.as_bytes().to_vec();
        if !source.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(name);
        if let Some(location) = read_tzif(&path_from_bytes(path)) {
            return Some(location);
        }
    }
    // The selected Headscale binary does not import time/tzdata. Go's
    // compiled defaultGOROOT is represented by the pinned archive, while an
    // explicit nonempty GOROOT exclusively selects its own archive.
    if let Some(root) = std::env::var_os("GOROOT").filter(|value| !value.is_empty()) {
        let mut path = os_bytes(&root);
        path.extend_from_slice(b"/lib/time/zoneinfo.zip");
        let mut source = Archive::file(&path_from_bytes(path))?;
        parse(&source.entry(name)?)
    } else {
        parse(&Archive::Bytes(ARCHIVE).entry(name)?)
    }
}

fn read_tzif(path: &Path) -> Option<Location> {
    let mut file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    // Go readFile reads 4096-byte blocks and rejects after crossing 10MiB.
    // Read no more than one byte past that public limit before rejecting.
    (&mut file)
        .take((10 << 20) + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 10 << 20 {
        return None;
    }
    parse(&bytes)
}

struct Data<'a>(&'a [u8]);
impl<'a> Data<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let value = self.0.get(..count)?;
        self.0 = &self.0[count..];
        Some(value)
    }
    fn counts(&mut self) -> Option<[usize; 6]> {
        let mut counts = [0; 6];
        for count in &mut counts {
            *count = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        }
        Some(counts)
    }
}

fn section_size(count: &[usize; 6], width: usize) -> Option<usize> {
    count[3]
        .checked_mul(width + 1)?
        .checked_add(count[4].checked_mul(6)?)?
        .checked_add(count[5])?
        .checked_add(count[2].checked_mul(width + 4)?)?
        .checked_add(count[1])?
        .checked_add(count[0])
}

fn parse(bytes: &[u8]) -> Option<Location> {
    let mut data = Data(bytes);
    if data.take(4)? != b"TZif" {
        return None;
    }
    let version = data.take(16)?[0];
    if !matches!(version, 0 | b'2' | b'3') {
        return None;
    }
    let mut counts = data.counts()?;
    let width = if version == 0 {
        4
    } else {
        data.take(section_size(&counts, 4)?.checked_add(20)?)?;
        counts = data.counts()?;
        8
    };
    // Validate every count against the input before allocating vectors.
    data.0.get(..section_size(&counts, width)?)?;
    let times = data.take(counts[3].checked_mul(width)?)?;
    let indices = data.take(counts[3])?;
    let types = data.take(counts[4].checked_mul(6)?)?;
    let names = data.take(counts[5])?;
    data.take(counts[2].checked_mul(width + 4)?)?;
    data.take(counts[1])?;
    data.take(counts[0])?;
    if counts[4] == 0 {
        return None;
    }
    let mut zones = Vec::with_capacity(counts[4]);
    for record in types.chunks_exact(6) {
        let offset = i32::from_be_bytes(record[..4].try_into().ok()?);
        let rest = names.get(usize::from(record[5])..)?;
        if rest.is_empty() {
            return None;
        }
        let length = rest
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(rest.len());
        zones.push(Zone {
            name: rest[..length].to_vec(),
            offset,
            dst: record[4] != 0,
        });
    }
    let mut transitions = Vec::with_capacity(counts[3]);
    for (time, index) in times.chunks_exact(width).zip(indices) {
        let seconds = if width == 4 {
            i64::from(i32::from_be_bytes(time.try_into().ok()?))
        } else {
            i64::from_be_bytes(time.try_into().ok()?)
        };
        let index = usize::from(*index);
        if index >= zones.len() {
            return None;
        }
        transitions.push((seconds, index));
    }
    if transitions.is_empty() {
        transitions.push((i64::MIN, 0));
    }
    let rest = data.0;
    let extension = if rest.len() > 2 && rest.first() == Some(&b'\n') && rest.last() == Some(&b'\n')
    {
        rest[1..rest.len() - 1].to_vec()
    } else {
        Vec::new()
    };
    Some(Location {
        zones,
        transitions,
        extension,
    })
}

enum Archive<'a> {
    Bytes(&'a [u8]),
    File(File, u64),
}

impl Archive<'_> {
    fn file(path: &Path) -> Option<Self> {
        let file = File::open(path).ok()?;
        let length = file.metadata().ok()?.len();
        Some(Self::File(file, length))
    }
    fn len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::File(_, length) => *length,
        }
    }
    fn range(&mut self, offset: u64, count: usize) -> Option<Vec<u8>> {
        if offset.checked_add(count as u64)? > self.len() {
            return None;
        }
        match self {
            Self::Bytes(bytes) => Some(
                bytes
                    .get(usize::try_from(offset).ok()?..)?
                    .get(..count)?
                    .to_vec(),
            ),
            Self::File(file, _) => {
                file.seek(SeekFrom::Start(offset)).ok()?;
                let mut bytes = vec![0; count];
                file.read_exact(&mut bytes).ok()?;
                Some(bytes)
            }
        }
    }
    fn entry(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        let tail = self.range(self.len().checked_sub(22)?, 22)?;
        if little4(&tail, 0)? != 0x06054b50 {
            return None;
        }
        let entries = little2(&tail, 10)?;
        let size = little4(&tail, 12)? as usize;
        let offset = u64::from(little4(&tail, 16)?);
        let central = self.range(offset, size)?;
        let mut rest = central.as_slice();
        for _ in 0..entries {
            if little4(rest, 0)? != 0x02014b50 {
                return None;
            }
            let method = little2(rest, 10)?;
            let size = little4(rest, 24)? as usize;
            let length = usize::from(little2(rest, 28)?);
            let extra = usize::from(little2(rest, 30)?);
            let comment = usize::from(little2(rest, 32)?);
            let offset = u64::from(little4(rest, 42)?);
            let entry_name = rest.get(46..46_usize.checked_add(length)?)?;
            let next = 46_usize
                .checked_add(length)?
                .checked_add(extra)?
                .checked_add(comment)?;
            rest = rest.get(next..)?;
            if entry_name != name {
                continue;
            }
            if method != 0 {
                return None;
            }
            let header = self.range(offset, 30_usize.checked_add(length)?)?;
            if little4(&header, 0)? != 0x04034b50
                || little2(&header, 8)? != method
                || usize::from(little2(&header, 26)?) != length
                || header.get(30..)? != name
            {
                return None;
            }
            let extra = u64::from(little2(&header, 28)?);
            return self.range(
                offset
                    .checked_add(30)?
                    .checked_add(length as u64)?
                    .checked_add(extra)?,
                size,
            );
        }
        None
    }
}

fn little2(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn little4(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
