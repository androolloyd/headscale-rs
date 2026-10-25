// Copyright 2020 The Go Authors. All rights reserved.
// Copyright 2023 The Go Authors. All rights reserved.
// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Headscale's HuJSON metadata pass followed by JSON v2 name validation.
//! Kept object members are checked before a serde map can discard duplicates.
//! Typed kind gates and error rendering adapt the pinned JSON experiment's
//! arshal_default.go, arshal_methods.go, and errors.go; see the retained license.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::go_json::{self, Cursor};

mod string_syntax;

// jsontext/state.go limits both token decoding and ReadValue to 10,000
// containers, counting the decoder's enclosing containers as well. The policy
// value built from the prepared bytes is consumed recursively afterwards
// (metadata stripping, serde decoding, clone/eq/serialize, drop), and an
// alternating object/array document overflows a 2 MiB thread stack from about
// 5,000 containers in release builds (2,500 in debug). Bound policies well
// below that instead of aborting the process; no real policy comes close.
const MAX_NESTING_DEPTH: usize = 1_000;

#[derive(Clone, Copy)]
enum Schema {
    Plain,
    Any,
    Groups,
    Hosts,
    Policy,
    Acls,
    Acl,
    Destinations,
    Destination,
    Grants,
    Grant,
    App,
    AppValues,
    Attrs,
    Attr,
    AutoApprovers,
    Sshs,
    Ssh,
    Tests,
    Test,
    SshTests,
    SshTest,
    Protocol,
    AclAction,
    SshAction,
    SshCheckPeriod,
    ProtocolPorts,
    ProtocolPort,
    Aliases,
    Alias,
    TagOwners,
    Owners,
    Owner,
    ApproverRoutes,
    Approvers,
    Approver,
    SshSources,
    SshSource,
    SshDestinations,
    SshDestination,
    SshTestSource,
    Tags,
    Tag,
    Prefixes,
    Prefix,
    SshUsers,
    SshTestUsers,
    SshUser,
    Strings,
    String,
    Capabilities,
    Capability,
    Bool,
}

impl Schema {
    fn field(self, name: &str) -> Option<&'static str> {
        match self {
            Self::Policy => crate::go_policy_field_name(name),
            Self::Acl => crate::go_acl_field_name(name),
            Self::Grant => crate::go_grant_field_name(name),
            Self::Attr => crate::go_node_attr_field_name(name),
            Self::AutoApprovers => crate::go_auto_approvers_field_name(name),
            Self::Ssh => crate::go_ssh_field_name(name),
            Self::Test => crate::go_policy_test_field_name(name),
            Self::SshTest => crate::go_ssh_test_field_name(name),
            _ => None,
        }
    }

    fn member(self, name: &str, native: bool) -> Self {
        // Groups first decodes map[string]any; ProtocolPort first decodes any.
        // Preserve that decoder recursively without treating opaque fields or
        // typed policy fields as generic values.
        match self {
            Self::Any | Self::Groups | Self::ProtocolPort | Self::Destination => return Self::Any,
            Self::TagOwners => return Self::Owners,
            Self::ApproverRoutes => return Self::Approvers,
            Self::Hosts => return Self::String,
            Self::App => return Self::AppValues,
            _ => {}
        }
        match (self, self.field(name)) {
            (Self::Policy, Some("groups")) => Self::Groups,
            (Self::Policy, Some("hosts")) if native => Self::Hosts,
            (Self::Policy, Some("randomizeClientPort")) if native => Self::Bool,
            (Self::Policy, Some("acls")) => Self::Acls,
            (Self::Policy, Some("tagOwners")) => Self::TagOwners,
            (Self::Policy, Some("grants")) => Self::Grants,
            (Self::Policy, Some("nodeAttrs")) => Self::Attrs,
            (Self::Policy, Some("autoApprovers")) => Self::AutoApprovers,
            (Self::AutoApprovers, Some("routes")) => Self::ApproverRoutes,
            (Self::AutoApprovers, Some("exitNode")) => Self::Approvers,
            (Self::Policy, Some("ssh")) => Self::Sshs,
            (Self::Policy, Some("tests")) => Self::Tests,
            (Self::Policy, Some("sshTests")) => Self::SshTests,
            (Self::Acl | Self::Test, Some("proto")) => Self::Protocol,
            (Self::Acl, Some("action")) => Self::AclAction,
            (Self::Ssh, Some("action")) => Self::SshAction,
            (Self::Ssh, Some("checkPeriod")) => Self::SshCheckPeriod,
            (Self::Grant, Some("ip")) => Self::ProtocolPorts,
            (Self::Grant, Some("app")) if native => Self::App,
            (Self::Acl, Some("dst")) if native => Self::Destinations,
            (Self::Grant, Some("via")) => Self::Tags,
            (Self::Attr, Some("ipPool")) => Self::Prefixes,
            (Self::Attr, Some("attr")) if native => Self::Capabilities,
            (Self::Attr, Some("attr"))
            | (Self::Ssh, Some("acceptEnv"))
            | (Self::Test, Some("accept" | "deny")) => Self::Strings,
            (Self::Test, Some("src")) => Self::String,
            (Self::SshTest, Some("accept" | "deny" | "check")) if native => Self::SshTestUsers,
            (Self::Ssh, Some("users")) | (Self::SshTest, Some("accept" | "deny" | "check")) => {
                Self::SshUsers
            }
            (Self::Ssh, Some("src")) => Self::SshSources,
            (Self::Ssh, Some("dst")) => Self::SshDestinations,
            (Self::SshTest, Some("src")) => Self::SshTestSource,
            (Self::SshTest, Some("dst"))
            | (Self::Acl, Some("src"))
            | (Self::Grant, Some("src" | "dst"))
            | (Self::Attr, Some("target")) => Self::Aliases,
            _ => Self::Plain,
        }
    }

    fn element(self) -> Self {
        match self {
            Self::Any | Self::ProtocolPort | Self::Destination => Self::Any,
            Self::Acls => Self::Acl,
            Self::Grants => Self::Grant,
            Self::Attrs => Self::Attr,
            Self::Sshs => Self::Ssh,
            Self::Tests => Self::Test,
            Self::SshTests => Self::SshTest,
            Self::ProtocolPorts => Self::ProtocolPort,
            Self::Aliases => Self::Alias,
            Self::Owners => Self::Owner,
            Self::Approvers => Self::Approver,
            Self::SshSources => Self::SshSource,
            Self::SshDestinations => Self::SshDestination,
            Self::Tags => Self::Tag,
            Self::Prefixes => Self::Prefix,
            Self::SshUsers | Self::SshTestUsers => Self::SshUser,
            Self::Strings => Self::String,
            Self::Capabilities => Self::Capability,
            Self::Destinations => Self::Destination,
            _ => Self::Plain,
        }
    }

    // JSON-v2's default struct/map/slice/bool decoders consume one token,
    // then reject a mismatched kind without traversing a container. Custom
    // JSON receivers first ReadValue; these types name their inner decode.
    fn native_kind(self) -> Option<(u8, &'static str)> {
        Some(match self {
            Self::Policy => (b'{', "v2.Policy"),
            Self::Acl => (b'{', "v2.ACL"),
            Self::Grant => (b'{', "v2.Grant"),
            Self::Attr => (b'{', "v2.NodeAttrGrant"),
            Self::AutoApprovers => (b'{', "v2.AutoApproverPolicy"),
            Self::Ssh => (b'{', "v2.SSH"),
            Self::Test => (b'{', "v2.PolicyTest"),
            // SSHPolicyTest.UnmarshalJSON decodes an anonymous raw struct;
            // its reflect.Type string exceeds the renderer's 100-byte cap.
            Self::SshTest => (b'{', "struct"),
            Self::Groups => (b'{', "map[string]interface {}"),
            Self::Hosts => (b'{', "map[string]string"),
            Self::TagOwners => (b'{', "v2.TagOwners"),
            Self::ApproverRoutes => (b'{', "map[netip.Prefix]v2.AutoApprovers"),
            Self::App => (b'{', "tailcfg.PeerCapMap"),
            Self::Acls => (b'[', "[]v2.ACL"),
            Self::Grants => (b'[', "[]v2.Grant"),
            Self::Attrs => (b'[', "[]v2.NodeAttrGrant"),
            Self::Sshs => (b'[', "[]v2.SSH"),
            Self::Tests => (b'[', "[]v2.PolicyTest"),
            Self::SshTests => (b'[', "[]v2.SSHPolicyTest"),
            Self::Destinations => (b'[', "[]v2.AliasWithPorts"),
            Self::ProtocolPorts => (b'[', "[]v2.ProtocolPort"),
            Self::Aliases | Self::SshSources | Self::SshDestinations => (b'[', "[]v2.AliasEnc"),
            Self::Owners => (b'[', "[]v2.OwnerEnc"),
            Self::Approvers => (b'[', "[]v2.AutoApproverEnc"),
            Self::Tags => (b'[', "[]v2.Tag"),
            Self::Prefixes => (b'[', "[]netip.Prefix"),
            Self::SshUsers => (b'[', "v2.SSHUsers"),
            Self::SshTestUsers => (b'[', "[]v2.SSHUser"),
            Self::Strings => (b'[', "[]string"),
            Self::Capabilities => (b'[', "[]tailcfg.NodeCapability"),
            Self::AppValues => (b'[', "[]tailcfg.RawMessage"),
            Self::Bool => (b't', "bool"),
            _ => return None,
        })
    }

    fn custom_error_type(self) -> &'static str {
        match self {
            Self::Protocol => "v2.Protocol",
            Self::AclAction => "v2.Action",
            Self::SshAction => "v2.SSHAction",
            Self::SshCheckPeriod => "v2.SSHCheckPeriod",
            Self::Alias | Self::SshSource | Self::SshDestination => "v2.AliasEnc",
            Self::Owner => "v2.OwnerEnc",
            Self::Approver => "v2.AutoApproverEnc",
            Self::Tag => "v2.Tag",
            Self::Prefix => "netip.Prefix",
            Self::ProtocolPort => "v2.ProtocolPort",
            Self::Destination => "v2.AliasWithPorts",
            Self::SshSources => "v2.SSHSrcAliases",
            Self::SshDestinations => "v2.SSHDstAliases",
            Self::SshTest => "v2.SSHPolicyTest",
            Self::Groups => "v2.Groups",
            Self::Hosts => "v2.Hosts",
            Self::String | Self::SshUser | Self::SshTestSource => "string",
            Self::Capability => "tailcfg.NodeCapability",
            _ => unreachable!("schema does not return a custom semantic cause"),
        }
    }
}

fn custom_scalar(schema: Schema, raw: &[u8]) -> Result<Vec<u8>, String> {
    if matches!(schema, Schema::String | Schema::SshUser | Schema::Prefix) {
        // Go's string decoder clears null to "". Prefix uses the text-method
        // decoder, whose null branch clears the typed value without calling
        // UnmarshalText; empty text also decodes to that zero Prefix.
        let value: String = if raw == b"null" {
            String::new()
        } else {
            serde_json::from_slice(raw).map_err(|error| error.to_string())?
        };
        let value = match schema {
            Schema::SshUser => crate::go_unicode::trim_space(&value).to_owned(),
            Schema::Prefix if !value.is_empty() => crate::go_netip::parse_prefix_text(&value)?,
            _ => value,
        };
        return serde_json::to_vec(&value).map_err(|error| error.to_string());
    }
    if matches!(
        schema,
        Schema::Alias
            | Schema::Owner
            | Schema::Approver
            | Schema::SshSource
            | Schema::SshDestination
            | Schema::SshTestSource
    ) {
        // unmarshalPointer first decodes a Go string. Only AliasEnc trims
        // whitespace; OwnerEnc and AutoApproverEnc retain every decoded byte.
        let alias: String = if raw == b"null" {
            String::new()
        } else {
            serde_json::from_slice(raw).map_err(|error| error.to_string())?
        };
        let value = match schema {
            Schema::SshTestSource if crate::go_unicode::trim_space(&alias).is_empty() => {
                String::new()
            }
            Schema::Alias | Schema::SshSource | Schema::SshDestination | Schema::SshTestSource => {
                let alias =
                    crate::go_policy_shape::canonical_alias(crate::go_unicode::trim_space(&alias))?;
                if matches!(schema, Schema::SshSource | Schema::SshDestination) {
                    crate::validate_ssh_alias_type(&alias, matches!(schema, Schema::SshSource))?;
                }
                alias
            }
            Schema::Owner | Schema::Approver => {
                if !alias.contains('@')
                    && !alias.starts_with("group:")
                    && !alias.starts_with("tag:")
                {
                    let kind = if matches!(schema, Schema::Owner) {
                        "owner"
                    } else {
                        "auto approver"
                    };
                    return Err(format!(
                        "invalid {kind} format: {}",
                        crate::go_strconv::quote(&alias),
                    ));
                }
                alias
            }
            _ => unreachable!(),
        };
        return serde_json::to_vec(&value).map_err(|error| error.to_string());
    }
    if matches!(schema, Schema::ProtocolPort | Schema::Destination) {
        if raw.first() != Some(&b'"') {
            let kind = match raw.first() {
                Some(b'n') => "<nil>",
                Some(b't' | b'f') => "bool",
                Some(b'[') => "[]interface {}",
                Some(b'{') => "map[string]interface {}",
                _ => "float64",
            };
            return Err(format!("type not supported: {kind}"));
        }
        // Both methods first decode into any, so they unquote escapes.
        let value: String = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
        if matches!(schema, Schema::Destination) {
            let (alias, ports) = crate::split_go_destination_and_port(&value)?;
            crate::parse_go_port_ranges(&ports).map_err(|error| {
                format!(
                    "dst={}: port range {}: {error}",
                    crate::go_strconv::quote(&value),
                    crate::go_strconv::quote(&ports),
                )
            })?;
            crate::validate_go_acl_alias_syntax(&alias)?;
        } else {
            crate::normalize_grant_ip_spec(&value)?;
        }
        return serde_json::to_vec(&value).map_err(|error| error.to_string());
    }
    if raw.first() == Some(&b'"') {
        // Validate JSON-v2 string encoding, without unquoting it for the
        // custom Go UnmarshalJSON methods that inspect raw token bytes.
        serde_json::from_slice::<String>(raw).map_err(|error| error.to_string())?;
    }
    if matches!(schema, Schema::SshCheckPeriod) && raw == b"null" {
        return Ok(raw.to_vec()); // A nil pointer bypasses its custom method.
    }
    let token = std::str::from_utf8(raw).map_err(|error| error.to_string())?;
    let text = token.trim_matches('"');
    let value = match schema {
        Schema::Protocol => crate::canonical_go_protocol(text)?,
        Schema::AclAction => {
            if text != "accept" {
                return Err(format!(
                    "action={} is not supported: invalid ACL action",
                    crate::go_strconv::quote(text)
                ));
            }
            text.to_owned()
        }
        Schema::SshAction => {
            let text = crate::go_unicode::trim_space(text);
            if !matches!(text, "" | "accept" | "check") {
                return Err(format!(
                    "{} is not a valid action",
                    crate::go_strconv::quote(text)
                ));
            }
            text.to_owned()
        }
        Schema::SshCheckPeriod => {
            if text == "always" {
                text.to_owned()
            } else {
                crate::format_go_duration_nanos(crate::parse_duration_nanos(text)?)
            }
        }
        Schema::Tag => {
            // Tag.UnmarshalJSON sees raw bytes and only trims quote bytes;
            // it deliberately does not unquote escapes or trim whitespace.
            crate::validate_tag_name(text)?;
            text.to_owned()
        }
        _ => unreachable!("only custom scalar schemas reach this boundary"),
    };
    serde_json::to_vec(&value).map_err(|error| error.to_string())
}

struct Frame<'a> {
    object: bool,
    names: BTreeSet<String>,
    typed_names: Option<BTreeSet<String>>,
    written: bool,
    index: usize,
    strip_metadata: bool,
    token: Option<String>,
    schema: Schema,
    any_number_error: Option<String>,
    ssh_alias_error: Option<String>,
    ssh_test_src_error: Option<String>,
    resume: Option<(Cursor<'a>, usize)>,
    receiver_raw: Option<&'a [u8]>,
}

// Groups' map[string]any has already passed its syntax and binary64 decode
// before this semantic phase. Only strings and runtime type identities affect
// its validation; retain shallow placeholders for rejected nested values,
// rather than building a recursively owned tree just to report their types.
fn receiver_atom(raw: &[u8]) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    Ok(match raw.first() {
        Some(b'"') => {
            Value::String(serde_json::from_slice(raw).map_err(|error| error.to_string())?)
        }
        Some(b'n') => Value::Null,
        Some(b't') => Value::Bool(true),
        Some(b'f') => Value::Bool(false),
        Some(b'[') => Value::Array(Vec::new()),
        Some(b'{') => Value::Object(serde_json::Map::new()),
        _ => Value::Number(0.into()),
    })
}

fn validate_map_receiver(schema: Schema, raw: &[u8]) -> Result<(), String> {
    if raw == b"null" {
        // Both methods decode a nil raw map and complete with an empty map.
        return Ok(());
    }
    let groups = matches!(schema, Schema::Groups);
    let mut cursor = Cursor::new(raw);
    cursor.take(b'{')?;
    cursor.space();
    let mut members = serde_json::Map::new();
    while cursor.peek() != Some(b'}') {
        let key = cursor.quoted()?;
        let key: String = serde_json::from_slice(key.get()).map_err(|error| error.to_string())?;
        cursor.space();
        cursor.take(b':')?;
        let value = cursor.value_unbounded()?;
        let value = if groups && value.get().first() == Some(&b'[') {
            let mut elements = Cursor::new(value.get());
            elements.take(b'[')?;
            elements.space();
            let mut strings = Vec::new();
            while elements.peek() != Some(b']') {
                strings.push(receiver_atom(elements.value_unbounded()?.get())?);
                elements.space();
                if elements.peek() == Some(b',') {
                    elements.take(b',')?;
                    elements.space();
                }
            }
            elements.take(b']')?;
            elements.done()?;
            serde_json::Value::Array(strings)
        } else {
            receiver_atom(value.get())?
        };
        members.insert(key, value);
        cursor.space();
        if cursor.peek() == Some(b',') {
            cursor.take(b',')?;
            cursor.space();
        }
    }
    cursor.take(b'}')?;
    cursor.done()?;
    let value = serde_json::Value::Object(members);
    let checked = if groups {
        crate::validate_go_policy_groups(&value)
    } else {
        crate::normalize_go_hosts(value).map(|_| ())
    };
    checked.map_err(|error| match error {
        crate::PolicyParseError::Json(message) | crate::PolicyParseError::Schema(message) => {
            message
        }
    })
}

fn pointer(frames: &[Frame]) -> String {
    frames
        .iter()
        .filter_map(|frame| frame.token.as_deref())
        .fold(String::new(), |mut pointer, token| {
            let _ = write!(pointer, "/{}", token.replace('~', "~0").replace('/', "~1"));
            pointer
        })
}

fn value_pointer(frames: &[Frame], token: Option<&str>) -> String {
    let mut path = pointer(frames);
    if let Some(token) = token {
        path.push('/');
        path.push_str(&token.replace('~', "~0").replace('/', "~1"));
    }
    path
}

// errors.go's kind mismatches and raw method failures have no value excerpt.
// Like the existing float64 diagnostic, choose the process's "cannot"
// spelling of Go's randomized pair "cannot" / "unable to".
fn native_kind_error(
    kind: u8,
    go_type: &str,
    offset: usize,
    frames: &[Frame],
    token: Option<&str>,
    cause: Option<&str>,
) -> String {
    let pointer = value_pointer(frames, token);
    if pointer.contains("/via/") {
        return "via can only be a tag".to_owned();
    }
    let kind = match kind {
        b'{' => "object",
        b'[' => "array",
        b'\"' => "string",
        b't' | b'f' => "boolean",
        b'n' => "null",
        _ => "number",
    };
    let mut error =
        format!("parsing policy from bytes: json: cannot unmarshal JSON {kind} into Go {go_type}");
    if !pointer.is_empty() {
        error.push_str(" within ");
        error.push_str(&crate::go_strconv::quote(&truncate_pointer(&pointer, 100)));
    } else if offset > 0 {
        let _ = write!(error, " after offset {offset}");
    }
    if let Some(cause) = cause {
        error.push_str(": ");
        error.push_str(cause);
    }
    error
}

// Headscale unmarshalPolicy reshapes selected SemanticError causes after
// JSON v2 decoding. Keep this outside the preceding ReadValue syntax pass.
fn native_custom_error(
    schema: Schema,
    source: &[u8],
    raw: &[u8],
    frames: &[Frame],
    token: Option<&str>,
    error: &str,
) -> String {
    // JSONPointer retains the input member spelling. The pinned condition is
    // deliberately case-sensitive even though struct field matching is not.
    if value_pointer(frames, token).contains("/via/") {
        return "via can only be a tag".to_owned();
    }
    if error == "tag names must start with a letter, after 'tag:'" {
        return format!(
            "tagOwners[{}]: {error}",
            crate::go_strconv::quote(token.unwrap_or_default())
        );
    }
    native_kind_error(
        raw[0],
        schema.custom_error_type(),
        packed_offset(source, raw),
        frames,
        token,
        Some(error),
    )
}

fn packed_offset(source: &[u8], raw: &[u8]) -> usize {
    (raw.as_ptr() as usize)
        .checked_sub(source.as_ptr() as usize)
        .filter(|&start| start <= source.len() && raw.len() <= source.len() - start)
        .expect("native decoder span belongs to packed source")
}

fn truncate_pointer(pointer: &str, limit: usize) -> String {
    if pointer.len() <= limit {
        return pointer.to_owned();
    }
    let bytes = pointer.as_bytes();
    let mut left = limit / 2;
    let mut right = bytes.len() - limit / 2;
    if let Some(index) = bytes[..left].iter().rposition(|&byte| byte == b'/')
        && index > 0
    {
        left = index;
    }
    if let Some(index) = bytes[right..].iter().position(|&byte| byte == b'/') {
        right += index + 1;
    }
    while !pointer.is_char_boundary(left) {
        left -= 1;
    }
    while !pointer.is_char_boundary(right) {
        right += 1;
    }
    let removed = &pointer[left..right];
    let mut middle = match removed.bytes().filter(|&byte| byte == b'/').count() {
        0 => "…",
        1 => "…/…",
        _ => "…/…/…",
    };
    if removed.starts_with('/') && middle != "…" {
        middle = middle.strip_prefix('…').unwrap();
    }
    if removed.ends_with('/') && middle != "…" {
        middle = middle.strip_suffix('…').unwrap();
    }
    format!("{}{middle}{}", &pointer[..left], &pointer[right..])
}

fn duplicate_name(frames: &[Frame], name: &str, native: bool) -> String {
    let error = duplicate_name_at(&pointer(frames), name);
    if native {
        format!("parsing policy from bytes: {error}")
    } else {
        error
    }
}

fn duplicate_name_at(parent: &str, name: &str) -> String {
    let suffix = if parent.is_empty() {
        String::new()
    } else {
        format!(
            " within {}",
            crate::go_strconv::quote(&truncate_pointer(parent, 100))
        )
    };
    format!(
        "jsontext: duplicate object member name {}{suffix}",
        crate::go_strconv::quote(name)
    )
}

fn validate_any_number(
    raw: &[u8],
    frames: &[Frame],
    token: Option<&str>,
    native: bool,
) -> Result<(), String> {
    if !matches!(raw.first(), Some(b'-' | b'0'..=b'9')) {
        return Ok(());
    }
    // JSON v2's unmarshalValueAny calls strconv.ParseFloat(..., 64),
    // including inside arrays and objects, before the policy custom method
    // inspects the decoded value. Both parsers round decimal JSON numbers to
    // binary64; Go reports ErrRange precisely when that result is infinite.
    // Underflow to zero is valid. The JSON grammar was checked before walking.
    let text = std::str::from_utf8(raw).map_err(|error| error.to_string())?;
    if text.parse::<f64>().is_ok_and(f64::is_finite) {
        return Ok(());
    }
    let mut location = pointer(frames);
    if let Some(token) = token {
        location.push('/');
        location.push_str(&token.replace('~', "~0").replace('/', "~1"));
    }
    if native && location.contains("/via/") {
        return Err("via can only be a tag".to_owned());
    }
    let value = if raw.len() < 100 {
        format!(" {text}")
    } else {
        String::new()
    };
    let location = if location.is_empty() {
        String::new()
    } else {
        format!(
            " within {}",
            crate::go_strconv::quote(&truncate_pointer(&location, 100))
        )
    };
    // SemanticError chooses between "cannot" and "unable to" once per Go
    // process. Use its "cannot" spelling and retain the selected value/type,
    // pointer, and unwrapped strconv.ErrRange cause.
    let prefix = if native {
        "parsing policy from bytes: "
    } else {
        ""
    };
    Err(format!(
        "{prefix}json: cannot unmarshal JSON number{value} into Go float64{location}: value out of range"
    ))
}

pub(crate) fn prepare(raw: &str) -> Result<Vec<u8>, String> {
    let source = crate::strip_hujson(raw);
    prepare_standardized(source.as_bytes(), false)
}

pub(crate) fn prepare_standardized(bytes: &[u8], native_names: bool) -> Result<Vec<u8>, String> {
    // Native input already passed the complete HuJSON grammar/metadata Pack
    // pass. A whole-buffer v1 scan here would let a later excessive depth
    // outrank earlier typed unknown-name, string, or custom-method errors.
    if !native_names {
        go_json::validate_with_depth(bytes, MAX_NESTING_DEPTH)?;
    }
    let mut cursor = Cursor::new(bytes);
    let mut cursor_base = 0;
    let mut out = Vec::with_capacity(bytes.len());
    let mut frames = Vec::<Frame>::new();
    let mut pending = Some((true, None, Schema::Policy));
    while pending.is_some() || !frames.is_empty() {
        cursor.space();
        if let Some((strip_metadata, token, schema)) = pending.take() {
            // Raw-text JSON methods receive every JSON kind, including
            // containers. Native mode must let the method reject that raw
            // value here, before subsequent policy fields are decoded.
            // ProtocolPort instead decodes into any, including its numbers.
            if matches!(
                schema,
                Schema::Alias
                    | Schema::Owner
                    | Schema::Approver
                    | Schema::SshSource
                    | Schema::SshDestination
                    | Schema::SshTestSource
                    | Schema::Tag
                    | Schema::Prefix
                    | Schema::SshUser
                    | Schema::String
                    | Schema::Capability
            ) || (matches!(
                schema,
                Schema::ProtocolPort
                    | Schema::Destination
                    | Schema::Protocol
                    | Schema::AclAction
                    | Schema::SshAction
                    | Schema::SshCheckPeriod
            ) && (!matches!(cursor.peek(), Some(b'{' | b'['))
                || (native_names && !matches!(schema, Schema::ProtocolPort | Schema::Destination))))
            {
                let raw = if native_names {
                    cursor.value_unbounded()?
                } else {
                    cursor.value()?
                };
                if native_names {
                    // Default strings, text methods, and JSON methods all
                    // ReadValue first. Even a rejected object/array must
                    // pass its entire strict syntax/depth check here.
                    validate_read_value(bytes, raw.get(), &frames, token.as_deref())?;
                    if matches!(
                        schema,
                        Schema::String
                            | Schema::Capability
                            | Schema::Prefix
                            | Schema::SshUser
                            | Schema::Alias
                            | Schema::Owner
                            | Schema::Approver
                            | Schema::SshSource
                            | Schema::SshDestination
                            | Schema::SshTestSource
                    ) && !matches!(raw.get().first(), Some(b'"' | b'n'))
                    {
                        let (go_type, cause) = match schema {
                            Schema::Prefix => {
                                ("netip.Prefix", Some("JSON value must be string type"))
                            }
                            Schema::Capability => ("tailcfg.NodeCapability", None),
                            _ => ("string", None),
                        };
                        return Err(native_kind_error(
                            raw.get()[0],
                            go_type,
                            cursor_base + cursor.position() - raw.get().len(),
                            &frames,
                            token.as_deref(),
                            cause,
                        ));
                    }
                }
                if matches!(schema, Schema::ProtocolPort | Schema::Destination) {
                    validate_any_number(raw.get(), &frames, token.as_deref(), native_names)?;
                }
                // SSH list methods first parse every AliasEnc, then check
                // source/destination allowed kinds in a second loop. A later
                // malformed alias therefore wins over an earlier valid alias
                // of an unsupported SSH kind.
                let ssh_list =
                    native_names && matches!(schema, Schema::SshSource | Schema::SshDestination);
                let scalar_schema = if ssh_list {
                    Schema::Alias
                } else if matches!(schema, Schema::Capability) {
                    Schema::String
                } else {
                    schema
                };
                let value = if native_names && matches!(schema, Schema::SshTestSource) {
                    // SSHPolicyTest first decodes src as an ordinary string
                    // alongside all remaining raw fields, then parses Src.
                    // Keep ordinary string/type failures immediate; defer only
                    // the source alias semantic failure until that struct ends.
                    let string = custom_scalar(Schema::String, raw.get())?;
                    match custom_scalar(schema, raw.get()) {
                        Ok(value) => value,
                        Err(error) => {
                            frames
                                .iter_mut()
                                .rev()
                                .find(|frame| matches!(frame.schema, Schema::SshTest))
                                .expect("SSH test source belongs to its custom receiver")
                                .ssh_test_src_error = Some(error);
                            string
                        }
                    }
                } else {
                    custom_scalar(scalar_schema, raw.get()).map_err(|error| {
                        if native_names {
                            native_custom_error(
                                schema,
                                bytes,
                                raw.get(),
                                &frames,
                                token.as_deref(),
                                &error,
                            )
                        } else {
                            error
                        }
                    })?
                };
                if ssh_list {
                    let alias = serde_json::from_slice::<String>(&value)
                        .map_err(|error| error.to_string())?;
                    if let Err(error) =
                        crate::validate_ssh_alias_type(&alias, matches!(schema, Schema::SshSource))
                    {
                        frames
                            .iter_mut()
                            .rev()
                            .find(|frame| {
                                matches!(frame.schema, Schema::SshSources | Schema::SshDestinations)
                            })
                            .expect("SSH aliases belong to a custom SSH list")
                            .ssh_alias_error
                            .get_or_insert(error);
                    }
                }
                out.extend(value);
                continue;
            }
            // JSON v2 reads an entire custom-method value before invoking
            // Headscale's element decoders. Later syntax/name/string failures
            // therefore precede an earlier alias/owner semantic failure.
            let mut receiver_raw = None;
            let resume = if native_names
                && matches!(cursor.peek(), Some(b'{' | b'['))
                && matches!(
                    schema,
                    Schema::Aliases
                        | Schema::Owners
                        | Schema::Approvers
                        | Schema::SshSources
                        | Schema::SshDestinations
                        | Schema::Groups
                        | Schema::Hosts
                        | Schema::ProtocolPort
                        | Schema::Destination
                        | Schema::SshTest
                ) {
                let raw_start = cursor_base + cursor.position();
                let raw = cursor.value_unbounded()?;
                validate_read_value(bytes, raw.get(), &frames, token.as_deref())?;
                receiver_raw = Some(raw.get());
                Some((
                    std::mem::replace(&mut cursor, Cursor::new(raw.get())),
                    std::mem::replace(&mut cursor_base, raw_start),
                ))
            } else {
                None
            };
            if native_names {
                let kind = cursor.peek().expect("validated HuJSON value");
                let offset = cursor_base + cursor.position();
                // ReadToken must first admit the opening delimiter. Its
                // nesting failure precedes even an immediate kind mismatch.
                if matches!(kind, b'{' | b'[') && frames.len() >= MAX_NESTING_DEPTH {
                    return Err(string_syntax::depth_error(
                        offset,
                        &value_pointer(&frames, token.as_deref()),
                    ));
                }
                if let Some((expected, go_type)) = schema.native_kind()
                    && kind != b'n'
                    && kind != expected
                    && !(expected == b't' && kind == b'f')
                {
                    // ReadToken validates a string token before rejecting its
                    // type, but never visits a rejected container's children.
                    if kind == b'"' {
                        let raw = cursor.quoted()?;
                        string_syntax::validate(bytes, raw.get(), || {
                            value_pointer(&frames, token.as_deref())
                        })?;
                    }
                    return Err(native_kind_error(
                        kind,
                        go_type,
                        offset,
                        &frames,
                        token.as_deref(),
                        None,
                    ));
                }
            }
            match cursor.peek() {
                Some(b'{' | b'[') => {
                    let delimiter = cursor.peek().unwrap();
                    cursor.take(delimiter)?;
                    out.push(delimiter);
                    frames.push(Frame {
                        object: delimiter == b'{',
                        names: BTreeSet::new(),
                        typed_names: matches!(schema, Schema::TagOwners | Schema::ApproverRoutes)
                            .then(BTreeSet::new),
                        written: false,
                        index: 0,
                        strip_metadata,
                        token,
                        schema,
                        any_number_error: None,
                        ssh_alias_error: None,
                        ssh_test_src_error: None,
                        resume,
                        receiver_raw,
                    });
                }
                Some(b'"') => {
                    let value = cursor.quoted()?;
                    if native_names {
                        string_syntax::validate(bytes, value.get(), || {
                            value_pointer(&frames, token.as_deref())
                        })?;
                    }
                    // JSON v2 rejects invalid UTF-8 and unpaired surrogates.
                    serde_json::from_slice::<String>(value.get())
                        .map_err(|error| error.to_string())?;
                    out.extend_from_slice(value.get());
                }
                _ => {
                    let raw = if native_names {
                        cursor.value_unbounded()?
                    } else {
                        cursor.value()?
                    };
                    if matches!(schema, Schema::Any)
                        && let Err(error) =
                            validate_any_number(raw.get(), &frames, token.as_deref(), native_names)
                    {
                        // The outer JSON-method decoder first ReadValues
                        // the whole subtree, validating names and strings.
                        // Only its subsequent any decode parses numbers.
                        // Keep the first numeric error until that syntax
                        // pass is complete, even if a later name is invalid.
                        frames
                            .iter_mut()
                            .rev()
                            .find(|frame| {
                                matches!(
                                    frame.schema,
                                    Schema::Groups | Schema::ProtocolPort | Schema::Destination
                                )
                            })
                            .expect("any values belong to a policy custom decoder")
                            .any_number_error
                            .get_or_insert(error);
                    }
                    if native_names && matches!(schema, Schema::Groups | Schema::Hosts) {
                        // Non-null scalars were rejected by the inner map
                        // decoder above. Complete the accepted null receiver.
                        validate_map_receiver(schema, raw.get())?;
                    }
                    out.extend_from_slice(raw.get());
                }
            }
            continue;
        }
        let frame = frames.last_mut().unwrap();
        let close = if frame.object { b'}' } else { b']' };
        if cursor.peek() == Some(close) {
            cursor.take(close)?;
            if let Some(error) = frame.any_number_error.take() {
                return Err(error);
            }
            let mut semantic_error = frame
                .ssh_alias_error
                .take()
                .or_else(|| frame.ssh_test_src_error.take());
            if matches!(frame.schema, Schema::ProtocolPort | Schema::Destination) {
                // ProtocolPort first unmarshals the entire value into any.
                // Nested number/string/name errors therefore take precedence
                // over its later rejection of a non-string decoded value.
                let kind = if frame.object {
                    "map[string]interface {}"
                } else {
                    "[]interface {}"
                };
                semantic_error = Some(format!("type not supported: {kind}"));
            }
            out.push(close);
            let frame = frames.pop().expect("closing prepared container");
            if let Some(error) = semantic_error {
                return Err(if native_names {
                    native_custom_error(
                        frame.schema,
                        bytes,
                        frame.receiver_raw.expect("native custom receiver span"),
                        &frames,
                        frame.token.as_deref(),
                        &error,
                    )
                } else {
                    error
                });
            }
            if let Some(raw) = frame.receiver_raw
                && matches!(frame.schema, Schema::Groups | Schema::Hosts)
            {
                validate_map_receiver(frame.schema, raw).map_err(|cause| {
                    native_custom_error(
                        frame.schema,
                        bytes,
                        raw,
                        &frames,
                        frame.token.as_deref(),
                        &cause,
                    )
                })?;
            }
            if let Some((parent, parent_base)) = frame.resume {
                cursor = parent;
                cursor_base = parent_base;
            }
            continue;
        }
        if cursor.peek() == Some(b',') {
            cursor.take(b',')?;
            cursor.space();
        }
        if frame.object {
            let key = cursor.quoted()?;
            cursor.space();
            cursor.take(b':')?;
            cursor.space();
            // Headscale strips metadata before JSON v2 sees it. Removed
            // members, including their nested names, do not cause duplicates.
            let loose_name = go_json::unquote(key.get())?;
            if frame.strip_metadata && loose_name.starts_with('#') {
                if native_names {
                    cursor.value_unbounded()?;
                } else {
                    cursor.value()?;
                }
                continue;
            }
            if native_names && let Err(failure) = string_syntax::check(bytes, key.get()) {
                return Err(failure.render(&pointer(&frames)));
            }
            let name =
                serde_json::from_slice::<String>(key.get()).map_err(|error| error.to_string())?;
            if native_names
                && matches!(
                    frame.schema,
                    Schema::Policy
                        | Schema::Acl
                        | Schema::Grant
                        | Schema::Attr
                        | Schema::AutoApprovers
                        | Schema::Ssh
                        | Schema::Test
                        | Schema::SshTest
                )
                && frame.schema.field(&name).is_none()
            {
                // Go: fmt.Errorf("%w: %q", ErrUnknownField, name).
                return Err(format!(
                    "unknown field: {}",
                    crate::go_strconv::quote(&name)
                ));
            }
            let key_name = frame
                .schema
                .field(&name)
                .map_or_else(|| name.clone(), str::to_owned);
            if !frame.names.insert(key_name) {
                return Err(duplicate_name(&frames, &name, native_names));
            }
            let typed_key = if matches!(frame.schema, Schema::TagOwners) {
                // Tag.UnmarshalJSON trims raw quote bytes instead of decoding
                // escape spellings. JSON-name duplicates are checked above;
                // the typed map also checks duplicate resulting Tag values.
                let tag = std::str::from_utf8(key.get())
                    .map_err(|error| error.to_string())?
                    .trim_matches('"')
                    .to_owned();
                if let Err(error) = crate::validate_tag_name(&tag) {
                    return Err(if native_names {
                        native_custom_error(
                            Schema::Tag,
                            bytes,
                            key.get(),
                            &frames,
                            Some(&name),
                            &error,
                        )
                    } else if error == "tag names must start with a letter, after 'tag:'" {
                        format!("tagOwners[{}]: {error}", crate::go_strconv::quote(&name))
                    } else {
                        error
                    });
                }
                if !frame
                    .typed_names
                    .get_or_insert_with(BTreeSet::new)
                    .insert(tag.clone())
                {
                    return Err(duplicate_name(&frames, &name, native_names));
                }
                Some(tag)
            } else if matches!(frame.schema, Schema::ApproverRoutes) {
                // Prefix.UnmarshalText receives the decoded object name.
                // Empty text denotes its zero value; valid prefixes retain
                // host bits. Distinct JSON names can yield the same typed key.
                let prefix = if name.is_empty() {
                    String::new()
                } else {
                    match crate::go_netip::parse_prefix_text(&name) {
                        Ok(prefix) => prefix,
                        Err(error) => {
                            return Err(if native_names {
                                native_custom_error(
                                    Schema::Prefix,
                                    bytes,
                                    key.get(),
                                    &frames,
                                    Some(&name),
                                    &error,
                                )
                            } else {
                                error
                            });
                        }
                    }
                };
                if !frame
                    .typed_names
                    .get_or_insert_with(BTreeSet::new)
                    .insert(prefix.clone())
                {
                    return Err(duplicate_name(&frames, &name, native_names));
                }
                Some(prefix)
            } else {
                None
            };
            if frame.written {
                out.push(b',');
            }
            frame.written = true;
            if let Some(key) = typed_key {
                out.extend(serde_json::to_vec(&key).map_err(|error| error.to_string())?);
            } else {
                out.extend_from_slice(key.get());
            }
            out.push(b':');
            // The pinned stripper compares this literal name exactly.
            let schema = frame.schema.member(&name, native_names);
            pending = Some((frame.strip_metadata && name != "app", Some(name), schema));
        } else {
            if frame.written {
                out.push(b',');
            }
            frame.written = true;
            let token = frame.index.to_string();
            frame.index += 1;
            pending = Some((frame.strip_metadata, Some(token), frame.schema.element()));
        }
    }
    cursor.done()?;
    Ok(out)
}

/// The syntactic ReadValue pass preceding a custom UnmarshalJSON method.
/// Numbers retain their raw grammar/spelling; float parsing and all policy
/// semantics belong to the subsequent typed decode. No value tree is built.
fn validate_read_value(
    source: &[u8],
    raw: &[u8],
    outer: &[Frame],
    token: Option<&str>,
) -> Result<(), String> {
    struct SyntaxFrame {
        object: bool,
        names: BTreeSet<String>,
        index: usize,
        token: Option<String>,
    }
    fn path(base: &str, frames: &[SyntaxFrame], token: Option<&str>) -> String {
        let mut path = base.to_owned();
        for token in frames
            .iter()
            .filter_map(|frame| frame.token.as_deref())
            .chain(token)
        {
            path.push('/');
            path.push_str(&token.replace('~', "~0").replace('/', "~1"));
        }
        path
    }
    let base = value_pointer(outer, token);
    let raw_offset = (raw.as_ptr() as usize)
        .checked_sub(source.as_ptr() as usize)
        .filter(|&start| start <= source.len() && raw.len() <= source.len() - start)
        .expect("ReadValue span belongs to packed source");
    let mut cursor = Cursor::new(raw);
    let mut frames = Vec::<SyntaxFrame>::new();
    let mut pending = Some(None);
    while pending.is_some() || !frames.is_empty() {
        cursor.space();
        if let Some(token) = pending.take() {
            match cursor.peek() {
                Some(delimiter @ (b'{' | b'[')) => {
                    if outer.len() + frames.len() >= MAX_NESTING_DEPTH {
                        return Err(string_syntax::depth_error(
                            raw_offset + cursor.position(),
                            &path(&base, &frames, token.as_deref()),
                        ));
                    }
                    cursor.take(delimiter)?;
                    frames.push(SyntaxFrame {
                        object: delimiter == b'{',
                        names: BTreeSet::new(),
                        index: 0,
                        token,
                    });
                }
                Some(b'"') => {
                    let value = cursor.quoted()?;
                    string_syntax::validate(source, value.get(), || {
                        path(&base, &frames, token.as_deref())
                    })?;
                    serde_json::from_slice::<String>(value.get())
                        .map_err(|error| error.to_string())?;
                }
                _ => {
                    cursor.value_unbounded()?;
                }
            }
            continue;
        }
        let frame = frames.last_mut().expect("pending syntax container");
        let close = if frame.object { b'}' } else { b']' };
        if cursor.peek() == Some(close) {
            cursor.take(close)?;
            frames.pop();
            continue;
        }
        if cursor.peek() == Some(b',') {
            cursor.take(b',')?;
            cursor.space();
        }
        let token = if frame.object {
            let key = cursor.quoted()?;
            if let Err(failure) = string_syntax::check(source, key.get()) {
                return Err(failure.render(&path(&base, &frames, None)));
            }
            let name =
                serde_json::from_slice::<String>(key.get()).map_err(|error| error.to_string())?;
            if !frame.names.insert(name.clone()) {
                let mut parent = base;
                for token in frames.iter().filter_map(|frame| frame.token.as_deref()) {
                    parent.push('/');
                    parent.push_str(&token.replace('~', "~0").replace('/', "~1"));
                }
                return Err(format!(
                    "parsing policy from bytes: {}",
                    duplicate_name_at(&parent, &name)
                ));
            }
            cursor.space();
            cursor.take(b':')?;
            name
        } else {
            let token = frame.index.to_string();
            frame.index += 1;
            token
        };
        pending = Some(Some(token));
    }
    cursor.done()
}
