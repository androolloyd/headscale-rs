// Copyright (c) 2011-2019 Canonical Ltd
// Licensed under the Apache License, Version 2.0.
// Finite receiver/scalar/merge behavior adapts gopkg.in/yaml.v3 v3.0.1
// decode.go and resolve.go. YAML syntax remains the selected granit parser.
//! The DERP YAML receiver preserves scalar style, tags, duplicate spelling and
//! aliases before applying the pinned Go typed assignments. The arena owns
//! indices, so unknown deeply nested values never form a recursive Rust tree.

use std::collections::{HashMap, HashSet};
use std::{cell::RefCell, rc::Rc};

use base64::Engine as _;
use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle};

use super::{NativeDerpMap, NativeDerpNode, NativeDerpRegion};

type Result<T> = std::result::Result<T, String>;

#[derive(Clone)]
enum Node {
    Scalar { text: String, tag: String },
    Sequence(Vec<usize>),
    Mapping(Vec<usize>),
    Alias { target: usize, name: String },
}

struct Document {
    nodes: Vec<Node>,
    root: Option<usize>,
    null_mappings: HashSet<usize>,
    lines: Vec<usize>,
    tags: Vec<String>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum Key {
    String(String),
    Int(i64),
    Uint(u64),
    Bool(bool),
    Float(u64),
    Null,
}

enum Scalar {
    String,
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Timestamp,
}

#[derive(Clone, Copy)]
enum Keys {
    String,
    Int,
}

impl Document {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let source = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
            if !bytes.len().is_multiple_of(2) {
                return Err("yaml: incomplete UTF-16 character".into());
            }
            let little = bytes[0] == 0xff;
            let units = bytes[2..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    if little {
                        u16::from_le_bytes(*pair)
                    } else {
                        u16::from_be_bytes(*pair)
                    }
                })
                .collect::<Vec<_>>();
            String::from_utf16(&units).map_err(|_| "yaml: invalid UTF-16 character".to_owned())?
        } else {
            std::str::from_utf8(bytes)
                .map_err(|_| "yaml: invalid UTF-8 character".to_owned())?
                .to_owned()
        };
        let mut document = Self {
            nodes: Vec::new(),
            root: None,
            null_mappings: HashSet::new(),
            lines: Vec::new(),
            tags: Vec::new(),
        };
        let mut anchors = HashMap::new();
        let mut parents = Vec::new();
        for next in Parser::new_from_str(&source).keep_tags(true) {
            let (event, span) = next.map_err(|error| format!("yaml: {error}"))?;
            let mut null_mapping = false;
            let mut display_tag = String::new();
            let (node, anchor, container) = match event {
                Event::DocumentStart(_, version) => {
                    if version.is_some_and(|version| version.major != 1 || version.minor != 1) {
                        return Err("yaml: found incompatible YAML document".into());
                    }
                    continue;
                }
                Event::StreamEnd | Event::DocumentEnd => break,
                Event::SequenceEnd | Event::MappingEnd => {
                    let id = parents
                        .pop()
                        .ok_or_else(|| "yaml: unexpected container end".to_owned())?;
                    if let Node::Mapping(values) = &document.nodes[id]
                        && !values.len().is_multiple_of(2)
                    {
                        return Err("yaml: missing mapping value".into());
                    }
                    continue;
                }
                Event::Scalar(text, style, anchor, tag) => {
                    let mut tag = tag.map(|tag| tag.to_string()).unwrap_or_default();
                    if tag == "!" {
                        tag.clear();
                    }
                    display_tag = diagnostic_tag(&tag);
                    if tag.is_empty() && style != ScalarStyle::Plain {
                        tag = "!!str".into();
                        display_tag.clone_from(&tag);
                    } else if tag.is_empty() && text == "<<" {
                        tag = "!!merge".into();
                        display_tag.clone_from(&tag);
                    }
                    (
                        Node::Scalar {
                            text: text.into_owned(),
                            tag: short_tag(&tag).to_owned(),
                        },
                        anchor,
                        false,
                    )
                }
                Event::SequenceStart(_, anchor, tag) => {
                    display_tag = tag
                        .map(|tag| diagnostic_tag(&tag.to_string()))
                        .unwrap_or_default();
                    if display_tag.is_empty() || display_tag == "!" {
                        display_tag = "!!seq".into();
                    }
                    (Node::Sequence(Vec::new()), anchor, true)
                }
                Event::MappingStart(_, anchor, tag) => {
                    display_tag = tag
                        .map(|tag| diagnostic_tag(&tag.to_string()))
                        .unwrap_or_default();
                    if display_tag.is_empty() || display_tag == "!" {
                        display_tag = "!!map".into();
                    }
                    null_mapping = display_tag == "!!null";
                    (Node::Mapping(Vec::new()), anchor, true)
                }
                Event::Alias(anchor) => {
                    let target = *anchors
                        .get(&anchor)
                        .ok_or_else(|| "yaml: unknown anchor".to_owned())?;
                    let name = span
                        .byte_range()
                        .and_then(|range| source.get(range))
                        .unwrap_or_default()
                        .trim_start_matches('*')
                        .to_owned();
                    (Node::Alias { target, name }, 0, false)
                }
                // The stream start and presentation comments have no receiver value.
                _ => continue,
            };
            let id = document.nodes.len();
            document.nodes.push(node);
            document.lines.push(
                span.tag_start
                    .map_or(span.start.line(), |tag| tag.line().min(span.start.line())),
            );
            document.tags.push(display_tag);
            if null_mapping {
                document.null_mappings.insert(id);
            }
            if anchor != 0 {
                anchors.insert(anchor, id);
            }
            if let Some(parent) = parents.last().copied() {
                match &mut document.nodes[parent] {
                    Node::Mapping(values) | Node::Sequence(values) => values.push(id),
                    _ => return Err("yaml: invalid parent".into()),
                }
            } else if document.root.replace(id).is_some() {
                return Err("yaml: multiple root values".into());
            }
            if container {
                parents.push(id);
            }
        }
        if !parents.is_empty() {
            return Err("yaml: unfinished document".into());
        }
        Ok(document)
    }

    fn dereference(&self, mut id: usize) -> Result<usize> {
        let mut seen = HashSet::new();
        while let Node::Alias { target, .. } = &self.nodes[id] {
            if !seen.insert(id) {
                return Err("yaml: anchor value contains itself".into());
            }
            id = *target;
        }
        Ok(id)
    }

    fn scalar(&self, id: usize) -> Result<(&str, Scalar)> {
        let id = self.dereference(id)?;
        let Node::Scalar { text, tag } = &self.nodes[id] else {
            return Err("yaml: cannot unmarshal collection into scalar".into());
        };
        Ok((text, resolve(tag, text)?))
    }

    fn pointer_mapping(&self, id: usize) -> Result<()> {
        // prepare leaves a pointer undereferenced for a null-tagged mapping;
        // mapping then rejects the pointer kind. A scalar null is different:
        // it assigns a nil pointer through scalar/null.
        if self.null_mappings.contains(&self.dereference(id)?) {
            return Err("yaml: cannot unmarshal !!map into DERP pointer".into());
        }
        Ok(())
    }

    fn is_null(&self, id: usize) -> Result<bool> {
        let id = self.dereference(id)?;
        if let Node::Scalar { text, tag } = &self.nodes[id] {
            Ok(matches!(resolve(tag, text)?, Scalar::Null))
        } else {
            Ok(false)
        }
    }

    fn string(&self, id: usize) -> Result<String> {
        let id = self.dereference(id)?;
        let (text, scalar) = self.scalar(id)?;
        if matches!(scalar, Scalar::Null) {
            return Ok(String::new());
        }
        if matches!(&self.nodes[id], Node::Scalar { tag, .. } if tag == "binary") {
            let bytes = decode_binary(text)?;
            return Ok(go_utf8(&bytes));
        }
        Ok(text.to_owned())
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "matches Go float64(int) conversion"
    )]
    fn integer(&self, id: usize) -> Result<i64> {
        let (_, scalar) = self.scalar(id)?;
        match scalar {
            Scalar::Null => Ok(0),
            Scalar::Int(value) => Ok(value),
            Scalar::Uint(value) => value
                .try_into()
                .map_err(|_| "yaml: integer overflows int".into()),
            Scalar::Float(value) if value <= i64::MAX as f64 => Ok(float_to_int(value)),
            _ => Err("yaml: cannot unmarshal scalar into int".into()),
        }
    }

    fn boolean(&self, id: usize) -> Result<bool> {
        let (text, scalar) = self.scalar(id)?;
        let binary;
        let text = if matches!(&self.nodes[self.dereference(id)?], Node::Scalar { tag, .. } if tag == "binary")
        {
            binary = go_utf8(&decode_binary(text)?);
            binary.as_str()
        } else {
            text
        };
        match scalar {
            Scalar::Null => Ok(false),
            Scalar::Bool(value) => Ok(value),
            Scalar::String => match text {
                "y" | "Y" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" => Ok(true),
                "n" | "N" | "no" | "No" | "NO" | "off" | "Off" | "OFF" => Ok(false),
                _ => Err("yaml: cannot unmarshal scalar into bool".into()),
            },
            _ => Err("yaml: cannot unmarshal scalar into bool".into()),
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "matches Go float64(int) conversion"
    )]
    fn float(&self, id: usize) -> Result<f64> {
        match self.scalar(id)?.1 {
            Scalar::Null => Ok(0.0),
            Scalar::Int(value) => Ok(value as f64),
            Scalar::Uint(value) => Ok(value as f64),
            Scalar::Float(value) => Ok(value),
            _ => Err("yaml: cannot unmarshal scalar into float64".into()),
        }
    }

    fn sequence(&self, id: usize) -> Result<Option<&[usize]>> {
        if self.is_null(id)? {
            return Ok(None);
        }
        match &self.nodes[self.dereference(id)?] {
            Node::Sequence(values) => Ok(Some(values)),
            _ => Err("yaml: cannot unmarshal value into sequence".into()),
        }
    }

    fn key(&self, id: usize, mode: Option<Keys>) -> Result<Key> {
        match mode {
            Some(Keys::String) => self.string(id).map(Key::String),
            Some(Keys::Int) => self.integer(id).map(Key::Int),
            None => {
                let (text, value) = self.scalar(id)?;
                Ok(match value {
                    Scalar::String => Key::String(self.string(id)?),
                    Scalar::Timestamp => Key::String(text.to_owned()),
                    Scalar::Null => Key::Null,
                    Scalar::Bool(value) => Key::Bool(value),
                    Scalar::Int(value) => Key::Int(value),
                    Scalar::Uint(value) => Key::Uint(value),
                    Scalar::Float(value) => Key::Float(value.to_bits()),
                })
            }
        }
    }

    fn merge_key(&self, id: usize) -> bool {
        matches!(&self.nodes[id], Node::Scalar { text, tag } if text == "<<" && matches!(tag.as_str(), "" | "!" | "merge"))
    }

    fn duplicate_key(&self, left: usize, right: usize) -> bool {
        match (&self.nodes[left], &self.nodes[right]) {
            (Node::Scalar { text: left, .. }, Node::Scalar { text: right, .. })
            | (Node::Alias { name: left, .. }, Node::Alias { name: right, .. }) => left == right,
            (Node::Sequence(_), Node::Sequence(_)) | (Node::Mapping(_), Node::Mapping(_)) => true,
            _ => false,
        }
    }

    fn value(&self, id: usize) -> &str {
        match &self.nodes[id] {
            Node::Scalar { text, .. } => text,
            Node::Alias { name, .. } => name,
            _ => "",
        }
    }

    fn alias_error(&self, id: usize) -> String {
        format!("yaml: anchor '{}' value contains itself", self.value(id))
    }

    fn type_error(&self, id: usize, ty: &str) -> Result<String> {
        let tag = if self.tags[id].is_empty() {
            match &self.nodes[id] {
                Node::Scalar { text, .. } => scalar_tag(&resolve("", text)?).to_owned(),
                _ => String::new(),
            }
        } else {
            self.tags[id].clone()
        };
        let value = if matches!(tag.as_str(), "!!seq" | "!!map") {
            String::new()
        } else {
            let raw = self.value(id);
            let preview = if raw.len() > 10 {
                format!("{}...", go_utf8(&raw.as_bytes()[..7]))
            } else {
                raw.to_owned()
            };
            format!(" `{preview}`")
        };
        Ok(format!(
            "line {}: cannot unmarshal {tag}{value} into {ty}",
            self.lines[id]
        ))
    }

    fn duplicate_errors(&self, id: usize, errors: &mut Vec<String>) -> bool {
        let Node::Mapping(values) = &self.nodes[id] else {
            return false;
        };
        let before = errors.len();
        // decode.go visits the first occurrence, then all later matches.
        for (index, pair) in values.as_chunks::<2>().0.iter().enumerate() {
            for later in values.as_chunks::<2>().0.iter().skip(index + 1) {
                if self.duplicate_key(pair[0], later[0]) {
                    errors.push(format!(
                        "line {}: mapping key {} already defined at line {}",
                        self.lines[later[0]],
                        headscale_api_acl::go_strconv::quote(self.value(later[0])),
                        self.lines[pair[0]],
                    ));
                }
            }
        }
        errors.len() != before
    }

    /// Go applies explicit members before merge defaults, independently of
    /// their source position. A merge sequence uses its first matching member.
    fn mapping(&self, root: usize, mode: Keys) -> Result<Vec<(Key, usize)>> {
        if self.is_null(root)? {
            return Ok(Vec::new());
        }
        enum Work {
            Enter(usize, bool),
            Leave(usize),
        }
        let mut work = vec![Work::Enter(root, false)];
        let mut active = HashSet::new();
        let mut expanded = HashSet::new();
        let mut seen = HashSet::new();
        let mut output = Vec::new();
        while let Some(next) = work.pop() {
            let (id, merged) = match next {
                Work::Leave(id) => {
                    active.remove(&id);
                    expanded.insert(id);
                    continue;
                }
                Work::Enter(id, merged) => (self.dereference(id)?, merged),
            };
            if !active.insert(id) {
                return Err("yaml: anchor value contains itself".into());
            }
            if merged && expanded.contains(&id) {
                active.remove(&id);
                continue;
            }
            let Node::Mapping(values) = &self.nodes[id] else {
                return Err("yaml: map merge requires map or sequence of maps".into());
            };
            for (index, pair) in values.as_chunks::<2>().0.iter().enumerate() {
                for previous in values.as_chunks::<2>().0.iter().take(index) {
                    if self.duplicate_key(previous[0], pair[0]) {
                        return Err("yaml: mapping key already defined".into());
                    }
                }
            }
            let mut merge = None;
            for pair in values.as_chunks::<2>().0 {
                if self.merge_key(pair[0]) {
                    merge = Some(pair[1]);
                    continue;
                }
                // Null scalar keys do not assign a zero scalar map key in Go.
                if self.is_null(pair[0])? {
                    continue;
                }
                let key = self.key(pair[0], Some(mode))?;
                if !merged || seen.insert(key.clone()) {
                    output.push((key, pair[1]));
                }
            }
            if !merged && merge.is_some() {
                for pair in values.as_chunks::<2>().0 {
                    seen.insert(self.key(pair[0], None)?);
                }
            }
            work.push(Work::Leave(id));
            if let Some(merge) = merge {
                let merge = self.dereference(merge)?;
                match &self.nodes[merge] {
                    Node::Mapping(_) => work.push(Work::Enter(merge, true)),
                    Node::Sequence(values) => {
                        for id in values.iter().rev() {
                            let id = self.dereference(*id)?;
                            if !matches!(self.nodes[id], Node::Mapping(_)) {
                                return Err(
                                    "yaml: map merge requires map or sequence of maps".into()
                                );
                            }
                            work.push(Work::Enter(id, true));
                        }
                    }
                    _ => return Err("yaml: map merge requires map or sequence of maps".into()),
                }
            }
        }
        Ok(output)
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<NativeDerpMap> {
    let document = Document::parse(bytes)?;
    AliasBudget::check(&document)?;
    let mut map = NativeDerpMap::default();
    let Some(root) = document.root else {
        return Ok(map);
    };
    let mut fields = HashSet::new();
    for (key, value) in document.mapping(root, Keys::String)? {
        let Key::String(key) = key else {
            unreachable!()
        };
        unique_field(
            &mut fields,
            &key,
            &["regions", "homeparams", "omitdefaultregions"],
        )?;
        match key.as_str() {
            "regions" => {
                for (key, value) in document.mapping(value, Keys::Int)? {
                    let Key::Int(key) = key else { unreachable!() };
                    let region = if document.is_null(value)? {
                        None
                    } else {
                        Some(region(&document, value)?)
                    };
                    map.regions.insert(key, region);
                }
            }
            "omitdefaultregions" => {
                document.boolean(value)?;
            }
            "homeparams" => {
                document.pointer_mapping(value)?;
                let mut fields = HashSet::new();
                for (key, value) in document.mapping(value, Keys::String)? {
                    if key == Key::String("regionscore".into()) {
                        unique_field(&mut fields, "regionscore", &["regionscore"])?;
                        for (_, value) in document.mapping(value, Keys::Int)? {
                            document.float(value)?;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(map)
}

fn region(document: &Document, id: usize) -> Result<NativeDerpRegion> {
    document.pointer_mapping(id)?;
    let mut value = NativeDerpRegion::default();
    let mut fields = HashSet::new();
    for (key, id) in document.mapping(id, Keys::String)? {
        let Key::String(key) = key else {
            unreachable!()
        };
        unique_field(
            &mut fields,
            &key,
            &[
                "regionid",
                "regioncode",
                "regionname",
                "latitude",
                "longitude",
                "avoid",
                "nomeasurenohome",
                "nodes",
            ],
        )?;
        match key.as_str() {
            "regionid" => value.region_id = document.integer(id)?,
            "regioncode" => value.region_code = document.string(id)?,
            "regionname" => value.region_name = document.string(id)?,
            "latitude" => value.latitude = document.float(id)?,
            "longitude" => value.longitude = document.float(id)?,
            "avoid" => value.avoid = document.boolean(id)?,
            "nomeasurenohome" => value.no_measure_no_home = document.boolean(id)?,
            "nodes" => {
                value.nodes = document
                    .sequence(id)?
                    .map(|nodes| {
                        nodes
                            .iter()
                            .map(|id| {
                                if document.is_null(*id)? {
                                    Ok(None)
                                } else {
                                    node(document, *id).map(Some)
                                }
                            })
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?;
            }
            _ => {}
        }
    }
    Ok(value)
}

fn node(document: &Document, id: usize) -> Result<NativeDerpNode> {
    document.pointer_mapping(id)?;
    let mut value = NativeDerpNode::default();
    let mut fields = HashSet::new();
    for (key, id) in document.mapping(id, Keys::String)? {
        let Key::String(key) = key else {
            unreachable!()
        };
        unique_field(
            &mut fields,
            &key,
            &[
                "name",
                "regionid",
                "hostname",
                "certname",
                "ipv4",
                "ipv6",
                "derpport",
                "stunport",
                "stunonly",
                "insecurefortests",
                "stuntestip",
                "canport80",
            ],
        )?;
        match key.as_str() {
            "name" => value.name = document.string(id)?,
            "regionid" => value.region_id = document.integer(id)?,
            "hostname" => value.host_name = document.string(id)?,
            "certname" => value.cert_name = document.string(id)?,
            "ipv4" => value.ipv4 = document.string(id)?,
            "ipv6" => value.ipv6 = document.string(id)?,
            "derpport" => value.derp_port = document.integer(id)?,
            "stunport" => value.stun_port = document.integer(id)?,
            "stunonly" => value.stun_only = document.boolean(id)?,
            "insecurefortests" => value.insecure_for_tests = document.boolean(id)?,
            "stuntestip" => value.stun_test_ip = document.string(id)?,
            "canport80" => value.can_port80 = document.boolean(id)?,
            _ => {}
        }
    }
    Ok(value)
}

fn unique_field(seen: &mut HashSet<String>, key: &str, known: &[&str]) -> Result<()> {
    if known.contains(&key) && !seen.insert(key.to_owned()) {
        return Err(format!("yaml: field {key} already set in DERP receiver"));
    }
    Ok(())
}

/// Walk the selected decoder's typed unmarshal operations before allocating
/// expanded canonical slices. Saved type errors continue through siblings;
/// fatal resolver/alias/merge failures override them. Alias depth belongs to
/// the whole target invocation, including its descendants; parser events and
/// unknown struct values are not decode operations. The explicit work stack
/// also keeps arbitrarily long merge chains off the Rust call stack.
#[derive(Default)]
struct AliasBudget {
    decodes: usize,
    aliases: usize,
    errors: Vec<String>,
}

#[derive(Clone, Copy)]
enum Receiver {
    Map,
    Regions,
    Region,
    Nodes,
    Node,
    Home,
    Scores,
    String,
    Int,
    Bool,
    Float,
}

type MergedKeys = Rc<RefCell<HashSet<Key>>>;

struct MappingWalk {
    id: usize,
    at: usize,
    receiver: Receiver,
    depth: usize,
    merged: Option<MergedKeys>,
    done: HashSet<String>,
    merge: Option<usize>,
}

impl Receiver {
    fn ty(self) -> &'static str {
        match self {
            Self::Map => "tailcfg.DERPMap",
            Self::Regions => "map[int]*tailcfg.DERPRegion",
            Self::Region => "tailcfg.DERPRegion",
            Self::Nodes => "[]*tailcfg.DERPNode",
            Self::Node => "tailcfg.DERPNode",
            Self::Home => "tailcfg.DERPHomeParams",
            Self::Scores => "map[int]float64",
            Self::String => "string",
            Self::Int => "int",
            Self::Bool => "bool",
            Self::Float => "float64",
        }
    }

    fn field(self, key: &str) -> Option<Self> {
        match (self, key) {
            (Self::Map, "regions") => Some(Self::Regions),
            (Self::Map, "homeparams") => Some(Self::Home),
            (Self::Home, "regionscore") => Some(Self::Scores),
            (Self::Region, "regionid") | (Self::Node, "regionid" | "derpport" | "stunport") => {
                Some(Self::Int)
            }
            (Self::Region, "regioncode" | "regionname")
            | (Self::Node, "name" | "hostname" | "certname" | "ipv4" | "ipv6" | "stuntestip") => {
                Some(Self::String)
            }
            (Self::Region, "latitude" | "longitude") => Some(Self::Float),
            (Self::Map, "omitdefaultregions")
            | (Self::Region, "avoid" | "nomeasurenohome")
            | (Self::Node, "stunonly" | "insecurefortests" | "canport80") => Some(Self::Bool),
            (Self::Region, "nodes") => Some(Self::Nodes),
            _ => None,
        }
    }

    fn keys(self) -> Keys {
        match self {
            Self::Regions | Self::Scores => Keys::Int,
            _ => Keys::String,
        }
    }
}

impl AliasBudget {
    #[allow(
        clippy::cast_precision_loss,
        reason = "matches Go float64(int) conversion"
    )]
    #[allow(
        clippy::suboptimal_flops,
        reason = "mirrors Go's unfused `0.99 - 0.89*x` so the ratio rounds identically"
    )]
    fn count(&mut self, depth: usize) -> Result<()> {
        self.decodes += 1;
        if depth > 0 {
            self.aliases += 1;
        }
        let allowed = if self.decodes <= 400_000 {
            0.99
        } else if self.decodes >= 4_000_000 {
            0.10
        } else {
            0.99 - 0.89 * ((self.decodes - 400_000) as f64 / 3_600_000.0)
        };
        if self.aliases > 100
            && self.decodes > 1000
            && self.aliases as f64 / self.decodes as f64 > allowed
        {
            return Err("yaml: document contains excessive aliasing".into());
        }
        Ok(())
    }

    /// All finite-schema map keys are scalar. Each alias and its target is a
    /// separate unmarshal invocation, just as for a typed scalar value.
    fn key(
        &mut self,
        document: &Document,
        mut id: usize,
        mut depth: usize,
        mode: Option<Keys>,
    ) -> Result<Option<Key>> {
        let mut active = HashSet::new();
        loop {
            self.count(depth)?;
            if let Node::Alias { target, .. } = &document.nodes[id] {
                if !active.insert(id) {
                    return Err(document.alias_error(id));
                }
                id = *target;
                depth += 1;
            } else {
                break;
            }
        }
        // null returns false for concrete scalar keys, but true for interface.
        if mode.is_some() && document.is_null(id)? {
            return Ok(None);
        }
        // Mapping checks raw duplicates even if the destination is scalar.
        if document.duplicate_errors(id, &mut self.errors) {
            return Ok(None);
        }
        if matches!(document.nodes[id], Node::Scalar { .. }) {
            document.scalar(id)?; // Invalid explicit tags are fatal, not saved.
        }
        match document.key(id, mode) {
            Ok(key) => Ok(Some(key)),
            Err(_) if mode.is_some() => {
                let ty = match mode {
                    Some(Keys::Int) => "int",
                    _ => "string",
                };
                self.errors.push(document.type_error(id, ty)?);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn check(document: &Document) -> Result<()> {
        enum Work {
            Decode(usize, Receiver, usize, Option<MergedKeys>),
            Mapping(MappingWalk),
            LeaveAlias(usize),
            Merge(usize, Receiver, usize, MergedKeys),
        }
        let mut budget = Self::default();
        // yaml.Unmarshal begins at the document node, even for empty input.
        if document.root.is_none() {
            return Ok(());
        }
        budget.count(0)?;
        let mut work = vec![Work::Decode(document.root.unwrap(), Receiver::Map, 0, None)];
        let mut active = HashSet::new();
        while let Some(next) = work.pop() {
            match next {
                Work::LeaveAlias(id) => {
                    active.remove(&id);
                }
                Work::Decode(id, receiver, depth, merged) => {
                    budget.count(depth)?;
                    if let Node::Alias { target, .. } = &document.nodes[id] {
                        if !active.insert(id) {
                            return Err(document.alias_error(id));
                        }
                        work.push(Work::LeaveAlias(id));
                        work.push(Work::Decode(*target, receiver, depth + 1, merged));
                        continue;
                    }
                    if document.is_null(id)? {
                        continue;
                    }
                    if document.duplicate_errors(id, &mut budget.errors) {
                        continue;
                    }
                    let null_pointer = merged.is_none()
                        && document.tags[id] == "!!null"
                        && matches!(receiver, Receiver::Region | Receiver::Node | Receiver::Home);
                    if null_pointer {
                        budget
                            .errors
                            .push(document.type_error(id, &format!("*{}", receiver.ty()))?);
                        continue;
                    }
                    let scalar_valid = match receiver {
                        Receiver::String => Some(document.string(id)),
                        Receiver::Int => Some(document.integer(id).map(|_| String::new())),
                        Receiver::Bool => Some(document.boolean(id).map(|_| String::new())),
                        Receiver::Float => Some(document.float(id).map(|_| String::new())),
                        _ => None,
                    };
                    if let Some(valid) = scalar_valid {
                        if valid.is_err() {
                            budget.errors.push(document.type_error(id, receiver.ty())?);
                        }
                        continue;
                    }
                    if matches!(receiver, Receiver::Nodes) {
                        let Node::Sequence(values) = &document.nodes[id] else {
                            budget.errors.push(document.type_error(id, receiver.ty())?);
                            continue;
                        };
                        work.extend(
                            values
                                .iter()
                                .rev()
                                .map(|id| Work::Decode(*id, Receiver::Node, depth, None)),
                        );
                    } else {
                        if !matches!(document.nodes[id], Node::Mapping(_)) {
                            budget.errors.push(document.type_error(id, receiver.ty())?);
                            continue;
                        }
                        work.push(Work::Mapping(MappingWalk {
                            id,
                            at: 0,
                            receiver,
                            depth,
                            merged,
                            done: HashSet::new(),
                            merge: None,
                        }));
                    }
                }
                Work::Mapping(mut walk) => {
                    let Node::Mapping(values) = &document.nodes[walk.id] else {
                        unreachable!()
                    };
                    if walk.at < values.len() {
                        let key_id = values[walk.at];
                        let value_id = values[walk.at + 1];
                        walk.at += 2;
                        if document.merge_key(key_id) {
                            walk.merge = Some(value_id);
                            work.push(Work::Mapping(walk));
                            continue;
                        }
                        let Some(key) =
                            budget.key(document, key_id, walk.depth, Some(walk.receiver.keys()))?
                        else {
                            work.push(Work::Mapping(walk));
                            continue;
                        };
                        if walk
                            .merged
                            .as_ref()
                            .is_some_and(|seen| !seen.borrow_mut().insert(key.clone()))
                        {
                            work.push(Work::Mapping(walk));
                            continue;
                        }
                        let child = match (&key, walk.receiver) {
                            (_, Receiver::Regions) => Some(Receiver::Region),
                            (_, Receiver::Scores) => Some(Receiver::Float),
                            (Key::String(key), receiver) => {
                                let field = receiver.field(key);
                                if field.is_some() && !walk.done.insert(key.clone()) {
                                    budget.errors.push(format!(
                                        "line {}: field {key} already set in type {}",
                                        document.lines[key_id],
                                        receiver.ty(),
                                    ));
                                    work.push(Work::Mapping(walk));
                                    continue;
                                }
                                field
                            }
                            _ => None,
                        };
                        let depth = walk.depth;
                        work.push(Work::Mapping(walk));
                        if let Some(child) = child {
                            work.push(Work::Decode(value_id, child, depth, None));
                        }
                    } else if let Some(merge) = walk.merge {
                        let seen = if let Some(seen) = walk.merged {
                            seen
                        } else {
                            let mut seen = HashSet::new();
                            for pair in values.as_chunks::<2>().0 {
                                if let Some(key) =
                                    budget.key(document, pair[0], walk.depth, None)?
                                {
                                    seen.insert(key);
                                }
                            }
                            Rc::new(RefCell::new(seen))
                        };
                        match &document.nodes[merge] {
                            Node::Mapping(_) | Node::Alias { .. } => {
                                work.push(Work::Merge(merge, walk.receiver, walk.depth, seen));
                            }
                            Node::Sequence(values) => {
                                for id in values.iter().rev() {
                                    work.push(Work::Merge(
                                        *id,
                                        walk.receiver,
                                        walk.depth,
                                        seen.clone(),
                                    ));
                                }
                            }
                            Node::Scalar { .. } => {
                                return Err(
                                    "yaml: map merge requires map or sequence of maps as the value"
                                        .into(),
                                );
                            }
                        }
                    }
                }
                Work::Merge(id, receiver, depth, seen) => {
                    let target = document.dereference(id)?;
                    if !matches!(document.nodes[target], Node::Mapping(_)) {
                        return Err(
                            "yaml: map merge requires map or sequence of maps as the value".into(),
                        );
                    }
                    work.push(Work::Decode(id, receiver, depth, Some(seen)));
                }
            }
        }
        if budget.errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "yaml: unmarshal errors:\n  {}",
                budget.errors.join("\n  ")
            ))
        }
    }
}

fn diagnostic_tag(tag: &str) -> String {
    tag.strip_prefix("tag:yaml.org,2002:")
        .map_or_else(|| tag.to_owned(), |suffix| format!("!!{suffix}"))
}

fn scalar_tag(value: &Scalar) -> &'static str {
    match value {
        Scalar::String => "!!str",
        Scalar::Null => "!!null",
        Scalar::Bool(_) => "!!bool",
        Scalar::Int(_) | Scalar::Uint(_) => "!!int",
        Scalar::Float(_) => "!!float",
        Scalar::Timestamp => "!!timestamp",
    }
}

fn short_tag(tag: &str) -> &str {
    tag.strip_prefix("tag:yaml.org,2002:")
        .or_else(|| tag.strip_prefix("!!"))
        .unwrap_or(tag)
}

#[allow(
    clippy::cast_precision_loss,
    reason = "matches Go float64(int) conversion"
)]
fn resolve(tag: &str, text: &str) -> Result<Scalar> {
    if !matches!(
        tag,
        "" | "str" | "bool" | "int" | "float" | "null" | "timestamp"
    ) {
        if tag == "binary" {
            decode_binary(text)?;
        }
        return Ok(Scalar::String);
    }
    if tag == "str" {
        return Ok(Scalar::String);
    }
    let value = match text {
        "" | "~" | "null" | "Null" | "NULL" => Scalar::Null,
        "true" | "True" | "TRUE" => Scalar::Bool(true),
        "false" | "False" | "FALSE" => Scalar::Bool(false),
        ".nan" | ".NaN" | ".NAN" => Scalar::Float(f64::NAN),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => Scalar::Float(f64::INFINITY),
        "-.inf" | "-.Inf" | "-.INF" => Scalar::Float(f64::NEG_INFINITY),
        _ if matches!(tag, "" | "timestamp") && timestamp(text) => Scalar::Timestamp,
        _ => number(text).unwrap_or(Scalar::String),
    };
    let valid = match (&value, tag) {
        (_, "")
        | (Scalar::Null, "null")
        | (Scalar::Bool(_), "bool")
        | (Scalar::Int(_) | Scalar::Uint(_), "int")
        | (Scalar::Float(_), "float")
        | (Scalar::Timestamp, "timestamp") => true,
        (Scalar::Int(value), "float") => return Ok(Scalar::Float(*value as f64)),
        _ => false,
    };
    if valid {
        Ok(value)
    } else {
        Err(format!(
            "yaml: cannot decode {} `{text}` as a !!{tag}",
            scalar_tag(&value)
        ))
    }
}

fn number(text: &str) -> Option<Scalar> {
    if !text
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_digit() || b"+-.".contains(byte))
    {
        return None;
    }
    if text.starts_with('.')
        && text.as_bytes().iter().enumerate().any(|(at, byte)| {
            *byte == b'_'
                && (at == 0
                    || !text.as_bytes()[at - 1].is_ascii_digit()
                    || !text.as_bytes().get(at + 1).is_some_and(u8::is_ascii_digit))
        })
    {
        return None;
    }
    let plain = text.replace('_', "");
    let (negative, digits) = if let Some(rest) = plain.strip_prefix('-') {
        (true, rest)
    } else {
        (false, plain.strip_prefix('+').unwrap_or(&plain))
    };
    let (radix, digits) = if let Some(digits) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, digits)
    } else if let Some(digits) = digits
        .strip_prefix("0o")
        .or_else(|| digits.strip_prefix("0O"))
    {
        (8, digits)
    } else if let Some(digits) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        (2, digits)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    if !digits.is_empty()
        && digits.chars().all(|ch| ch.is_digit(radix))
        && let Ok(magnitude) = u64::from_str_radix(digits, radix)
    {
        if negative {
            if magnitude <= 1u64 << 63 {
                return Some(Scalar::Int(if magnitude == 1u64 << 63 {
                    i64::MIN
                } else {
                    -(magnitude as i64)
                }));
            }
        } else if let Ok(value) = i64::try_from(magnitude) {
            return Some(Scalar::Int(value));
        } else if !plain.starts_with('+') {
            return Some(Scalar::Uint(magnitude));
        }
    }
    // The selected resolver also retries the legacy lowercase 0b/0o
    // prefixes with an explicit base. ParseInt then permits a sign *after*
    // that prefix, even though the first base-zero parse rejected it.
    for (prefix, radix) in [("0b", 2), ("0o", 8)] {
        if let Some(rest) = plain.strip_prefix(prefix) {
            if let Ok(value) = i64::from_str_radix(rest, radix) {
                return Some(Scalar::Int(value));
            }
            if !matches!(rest.as_bytes().first(), Some(b'+' | b'-'))
                && let Ok(value) = u64::from_str_radix(rest, radix)
            {
                return Some(Scalar::Uint(value));
            }
        }
    }
    // yaml.v3 accepts decimal floats only, after removing all underscores.
    let bytes = plain.as_bytes();
    let mut at = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    let start = at;
    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    let before = at - start;
    let mut after = 0;
    if bytes.get(at) == Some(&b'.') {
        at += 1;
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        after = at - start;
    }
    if before + after == 0 {
        return None;
    }
    if matches!(bytes.get(at), Some(b'e' | b'E')) {
        at += 1;
        if matches!(bytes.get(at), Some(b'+' | b'-')) {
            at += 1;
        }
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start {
            return None;
        }
    }
    if at != bytes.len() {
        return None;
    }
    plain
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite())
        .map(Scalar::Float)
}

fn float_to_int(value: f64) -> i64 {
    // Go's x86 CVTT conversion returns MinInt64 at the rounded upper bound;
    // AArch64's FCVTZS saturates, as does Rust's float cast.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if value >= 9_223_372_036_854_775_808.0 {
        return i64::MIN;
    }
    value as i64
}

fn decode_binary(text: &str) -> Result<Vec<u8>> {
    let engine = base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::PAD.with_decode_allow_trailing_bits(true),
    );
    engine
        .decode(
            text.bytes()
                .filter(|byte| !matches!(byte, b'\r' | b'\n'))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| "yaml: !!binary value contains invalid base64 data".into())
}

fn go_utf8(bytes: &[u8]) -> String {
    let mut result = String::new();
    let mut at = 0;
    while at < bytes.len() {
        let width = match bytes[at] {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        };
        if let Some(text) = (width > 0)
            .then(|| bytes.get(at..at + width))
            .flatten()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
        {
            result.push_str(text);
            at += width;
        } else {
            result.push('\u{fffd}');
            at += 1;
        }
    }
    result
}

fn timestamp(text: &str) -> bool {
    fn take(bytes: &[u8], at: &mut usize, min: usize, max: usize) -> Option<u32> {
        let start = *at;
        let mut value = 0;
        while *at - start < max && bytes.get(*at).is_some_and(u8::is_ascii_digit) {
            value = value * 10 + u32::from(bytes[*at] - b'0');
            *at += 1;
        }
        (*at - start >= min).then_some(value)
    }
    fn parse(bytes: &[u8]) -> Option<()> {
        let mut at = 0;
        let year = take(bytes, &mut at, 4, 4)?;
        if bytes.get(at) != Some(&b'-') {
            return None;
        }
        at += 1;
        let month = take(bytes, &mut at, 1, 2)?;
        if bytes.get(at) != Some(&b'-') {
            return None;
        }
        at += 1;
        let day = take(bytes, &mut at, 1, 2)?;
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let max = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if leap {
                    29
                } else {
                    28
                }
            }
            _ => return None,
        };
        if day == 0 || day > max {
            return None;
        }
        if at == bytes.len() {
            return Some(());
        }
        let separator = *bytes.get(at)?;
        if !b"Tt ".contains(&separator) {
            return None;
        }
        at += 1;
        if separator == b' ' {
            while bytes.get(at) == Some(&b' ') {
                at += 1;
            }
        }
        let hour = take(bytes, &mut at, 1, 2)?;
        if bytes.get(at) != Some(&b':') {
            return None;
        }
        at += 1;
        let minute = take(bytes, &mut at, 1, 2)?;
        if bytes.get(at) != Some(&b':') {
            return None;
        }
        at += 1;
        let second = take(bytes, &mut at, 1, 2)?;
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        if matches!(bytes.get(at), Some(b'.' | b',')) {
            at += 1;
            let start = at;
            while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                at += 1;
            }
            if at == start {
                return None;
            }
        }
        if separator == b' ' {
            return (at == bytes.len()).then_some(());
        }
        if bytes.get(at) == Some(&b'Z') {
            at += 1;
        } else {
            if !matches!(bytes.get(at), Some(b'+' | b'-')) {
                return None;
            }
            at += 1;
            if take(bytes, &mut at, 2, 2)? > 24 {
                return None;
            }
            if bytes.get(at) != Some(&b':') {
                return None;
            }
            at += 1;
            if take(bytes, &mut at, 2, 2)? > 60 {
                return None;
            }
        }
        (at == bytes.len()).then_some(())
    }
    parse(text.as_bytes()).is_some()
}
