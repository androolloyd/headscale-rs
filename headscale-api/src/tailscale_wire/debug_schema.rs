// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
// tailscale.com v1.101.0-pre tailcfg, derpmap, tka and dnstype JSON schemas.
// See UPSTREAM.md and LICENSE-TAILSCALE.

//! Private schema metadata for native MapResponse debug readback.

use super::debug_nodes::{Kind, MapKey, MapValue, Omit, RESOLVER, Spec};

pub(super) const PROFILE: &[Spec] = &[
    ("ID", Kind::Int, Omit::Never),
    ("LoginName", Kind::Text, Omit::Never),
    ("DisplayName", Kind::Text, Omit::Never),
    ("ProfilePicURL", Kind::Text, Omit::Zero),
    ("Groups", Kind::Strings, Omit::Empty),
];

pub(super) const PING: &[Spec] = &[
    ("URL", Kind::Text, Omit::Never),
    ("URLIsNoise", Kind::Bool, Omit::Zero),
    ("Log", Kind::Bool, Omit::Zero),
    ("Types", Kind::Text, Omit::Zero),
    ("IP", Kind::Addr, Omit::Zero),
    ("Payload", Kind::Bytes, Omit::Empty),
];

pub(super) const DNS: &[Spec] = &[
    ("Resolvers", Kind::Resolvers, Omit::Empty),
    (
        "Routes",
        Kind::Map(MapKey::Text, MapValue::Records(RESOLVER, true)),
        Omit::Empty,
    ),
    ("FallbackResolvers", Kind::Resolvers, Omit::Empty),
    ("Domains", Kind::Strings, Omit::Empty),
    ("Proxied", Kind::Bool, Omit::Zero),
    ("Nameservers", Kind::Addresses, Omit::Empty),
    ("CertDomains", Kind::Strings, Omit::Empty),
    (
        "ExtraRecords",
        Kind::Records(DNS_RECORD, false),
        Omit::Empty,
    ),
    ("ExitNodeFilteredSet", Kind::Strings, Omit::Empty),
    ("TempCorpIssue13969", Kind::Text, Omit::Zero),
];

const DNS_RECORD: &[Spec] = &[
    ("Name", Kind::Text, Omit::Never),
    ("Type", Kind::Text, Omit::Zero),
    ("Value", Kind::Text, Omit::Never),
];

pub(super) const DISPLAY: &[Spec] = &[
    ("Title", Kind::Text, Omit::Never),
    ("Text", Kind::Text, Omit::Never),
    ("Severity", Kind::Text, Omit::Never),
    ("ImpactsConnectivity", Kind::Bool, Omit::Empty),
    ("PrimaryAction", Kind::Struct(DISPLAY_ACTION), Omit::Nil),
];

const DISPLAY_ACTION: &[Spec] = &[
    ("URL", Kind::Text, Omit::Never),
    ("Label", Kind::Text, Omit::Never),
];

pub(super) const CLIENT_VERSION: &[Spec] = &[
    ("RunningLatest", Kind::Bool, Omit::Empty),
    ("LatestVersion", Kind::Text, Omit::Empty),
    ("UrgentSecurityUpdate", Kind::Bool, Omit::Empty),
    ("Notify", Kind::Bool, Omit::Empty),
    ("NotifyURL", Kind::Text, Omit::Empty),
    ("NotifyText", Kind::Text, Omit::Empty),
];

pub(super) const DIAL_PLAN: &[Spec] = &[(
    "Candidates",
    Kind::Records(DIAL_CANDIDATE, false),
    Omit::Never,
)];

const DIAL_CANDIDATE: &[Spec] = &[
    ("IP", Kind::Addr, Omit::Zero),
    ("ACEHost", Kind::Text, Omit::Empty),
    ("DialStartDelaySec", Kind::Float, Omit::Empty),
    ("DialTimeoutSec", Kind::Float, Omit::Empty),
    ("Priority", Kind::Int, Omit::Empty),
];

pub(super) const DEBUG: &[Spec] = &[
    ("SleepSeconds", Kind::Float, Omit::Empty),
    ("DisableLogTail", Kind::Bool, Omit::Empty),
    ("Exit", Kind::OptionalInt, Omit::Nil),
];

pub(super) const TKA: &[Spec] = &[
    ("Head", Kind::Text, Omit::Empty),
    ("Disabled", Kind::Bool, Omit::Empty),
];

pub(super) const DERP: &[Spec] = &[
    ("HomeParams", Kind::Struct(DERP_HOME), Omit::Nil),
    (
        "Regions",
        Kind::Map(MapKey::Int, MapValue::Record(DERP_REGION)),
        Omit::Never,
    ),
    ("omitDefaultRegions", Kind::Bool, Omit::Empty),
];

const DERP_HOME: &[Spec] = &[(
    "RegionScore",
    Kind::Map(MapKey::Int, MapValue::Float),
    Omit::Empty,
)];

const DERP_REGION: &[Spec] = &[
    ("RegionID", Kind::Int, Omit::Never),
    ("RegionCode", Kind::Text, Omit::Never),
    ("RegionName", Kind::Text, Omit::Never),
    ("Latitude", Kind::Float, Omit::Empty),
    ("Longitude", Kind::Float, Omit::Empty),
    ("Avoid", Kind::Bool, Omit::Empty),
    ("NoMeasureNoHome", Kind::Bool, Omit::Empty),
    ("Nodes", Kind::Records(DERP_NODE, true), Omit::Never),
];

const DERP_NODE: &[Spec] = &[
    ("Name", Kind::Text, Omit::Never),
    ("RegionID", Kind::Int, Omit::Never),
    ("HostName", Kind::Text, Omit::Never),
    ("CertName", Kind::Text, Omit::Empty),
    ("IPv4", Kind::Text, Omit::Empty),
    ("IPv6", Kind::Text, Omit::Empty),
    ("STUNPort", Kind::Int, Omit::Empty),
    ("STUNOnly", Kind::Bool, Omit::Empty),
    ("DERPPort", Kind::Int, Omit::Empty),
    ("InsecureForTests", Kind::Bool, Omit::Empty),
    ("STUNTestIP", Kind::Text, Omit::Empty),
    ("CanPort80", Kind::Bool, Omit::Empty),
];

pub(super) const SSH_POLICY: &[Spec] = &[("rules", Kind::Records(SSH_RULE, true), Omit::Never)];

const SSH_RULE: &[Spec] = &[
    ("ruleExpires", Kind::OptionalTime, Omit::Nil),
    (
        "principals",
        Kind::Records(SSH_PRINCIPAL, true),
        Omit::Never,
    ),
    (
        "sshUsers",
        Kind::Map(MapKey::Text, MapValue::Text),
        Omit::Never,
    ),
    ("action", Kind::Struct(SSH_ACTION), Omit::Never),
    ("acceptEnv", Kind::Strings, Omit::Empty),
];

const SSH_PRINCIPAL: &[Spec] = &[
    ("node", Kind::Text, Omit::Empty),
    ("nodeIP", Kind::Text, Omit::Empty),
    ("userLogin", Kind::Text, Omit::Empty),
    ("any", Kind::Bool, Omit::Empty),
    ("pubKeys", Kind::Strings, Omit::Empty),
];

pub(super) const SSH_ACTION: &[Spec] = &[
    ("message", Kind::Text, Omit::Empty),
    ("reject", Kind::Bool, Omit::Empty),
    ("accept", Kind::Bool, Omit::Empty),
    ("sessionDuration", Kind::Int, Omit::Empty),
    ("allowAgentForwarding", Kind::Bool, Omit::Empty),
    ("holdAndDelegate", Kind::Text, Omit::Empty),
    ("allowLocalPortForwarding", Kind::Bool, Omit::Empty),
    ("allowRemotePortForwarding", Kind::Bool, Omit::Empty),
    ("recorders", Kind::Endpoints, Omit::Empty),
    (
        "onRecordingFailure",
        Kind::Struct(SSH_RECORDING_FAILURE),
        Omit::Nil,
    ),
];

const SSH_RECORDING_FAILURE: &[Spec] = &[
    ("RejectSessionWithMessage", Kind::Text, Omit::Empty),
    ("TerminateSessionWithMessage", Kind::Text, Omit::Empty),
    ("NotifyURL", Kind::Text, Omit::Empty),
];
