//! Finite native resource DTOs. In particular, identifier decoding never uses
//! serde's adjacent-tagged Content buffer for arbitrarily nested input values.

use serde::Deserialize;

use super::{NativeAuthorization, NativeChallenge, native_error, null_string, null_vec};
use crate::{
    Authorization, AuthorizationState, AuthorizationStatus, Challenge, ChallengeStatus,
    ChallengeType, Error, Identifier, OrderState, OrderStatus, Problem, Subproblem,
};

/// A native string-valued identifier, including types absent from the SDK enum.
#[derive(Clone, Default, Debug, Deserialize)]
#[non_exhaustive]
pub struct NativeIdentifier {
    /// Original identifier type.
    #[serde(rename = "type", default, deserialize_with = "null_string")]
    pub kind: String,
    /// Original identifier value.
    #[serde(default, deserialize_with = "null_string")]
    pub value: String,
}

impl NativeIdentifier {
    fn into_identifier(self) -> Result<Identifier, Error> {
        match self.kind.as_str() {
            "dns" => Ok(Identifier::Dns(self.value)),
            "ip" => self
                .value
                .parse()
                .map(Identifier::Ip)
                .map_err(|error| native_error(format!("invalid native IP identifier: {error}"))),
            "permanent-identifier" => Ok(Identifier::PermanentIdentifier(self.value)),
            "hardware-module" => Ok(Identifier::HardwareModule(self.value)),
            // Go retains arbitrary identifier types. The existing public SDK
            // enum cannot represent them; preserve that projection boundary.
            _ => Err(native_error("unsupported native identifier type")),
        }
    }
}

/// Raw native problem metadata before projection into the SDK error model.
#[derive(Clone, Default, Debug, Deserialize)]
#[non_exhaustive]
pub struct NativeProblem {
    /// Original problem type.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// Original human-readable detail.
    pub detail: Option<String>,
    /// Original problem instance URL.
    pub instance: Option<String>,
    /// Native signed platform-integer status, including values outside u16.
    pub status: Option<i64>,
    /// Native subproblems, retaining arbitrary identifier type/value strings.
    #[serde(default, deserialize_with = "null_vec")]
    pub subproblems: Vec<NativeSubproblem>,
}

/// A native subproblem whose identifier need not fit the SDK identifier enum.
#[derive(Clone, Default, Debug, Deserialize)]
#[non_exhaustive]
pub struct NativeSubproblem {
    /// Original native identifier.
    pub identifier: Option<NativeIdentifier>,
    /// Original problem type.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// Original subproblem instance URL.
    pub instance: Option<String>,
    /// Original human-readable detail.
    pub detail: Option<String>,
}

impl NativeProblem {
    pub(super) fn into_problem(self) -> Result<Problem, Error> {
        Ok(Problem {
            r#type: self.kind,
            detail: self.detail,
            status: self
                .status
                .map(u16::try_from)
                .transpose()
                .map_err(|_| native_error("native problem status does not fit SDK u16"))?,
            subproblems: self
                .subproblems
                .into_iter()
                .map(|problem| {
                    Ok(Subproblem {
                        identifier: problem
                            .identifier
                            .map(NativeIdentifier::into_identifier)
                            .transpose()?,
                        r#type: problem.kind,
                        detail: problem.detail,
                    })
                })
                .collect::<Result<_, Error>>()?,
        })
    }
}

/// Latest decoded native order resource, without an SDK status interpretation.
#[derive(Clone, Default, Debug, Deserialize)]
#[non_exhaustive]
pub struct NativeOrderResource {
    /// Original, case-sensitive status, including unknown values.
    #[serde(default, deserialize_with = "null_string")]
    pub status: String,
    /// Validated original expiry timestamp, if provided.
    pub expires: Option<String>,
    /// Validated original not-before timestamp, if provided.
    pub not_before: Option<String>,
    /// Validated original not-after timestamp, if provided.
    pub not_after: Option<String>,
    /// Native string-valued identifiers, including unknown types.
    #[serde(default)]
    pub identifiers: Vec<NativeIdentifier>,
    /// Original authorization URLs.
    #[serde(default, deserialize_with = "null_vec")]
    pub authorizations: Vec<String>,
    /// Original CSR finalization URL.
    #[serde(default, deserialize_with = "null_string")]
    pub finalize: String,
    /// Original certificate URL.
    pub certificate: Option<String>,
    /// Original problem metadata, independent of SDK representability.
    pub error: Option<NativeProblem>,
    /// Location header on this response, including missing/empty.
    #[serde(skip)]
    pub location: String,
}

pub(super) type NativeOrderWire = NativeOrderResource;

impl NativeOrderResource {
    pub(super) fn project_state(&self) -> Result<OrderState, Error> {
        let status = match self.status.as_str() {
            "pending" => OrderStatus::Pending,
            "ready" => OrderStatus::Ready,
            "processing" => OrderStatus::Processing,
            "valid" => OrderStatus::Valid,
            "invalid" => OrderStatus::Invalid,
            _ => return Err(native_error("acme: unknown native order status")),
        };
        // SDK error metadata is a projection; retain the full raw resource in
        // the native sidecar when status/identifier types are unrepresentable.
        let projected_problem = self
            .error
            .clone()
            .and_then(|problem| problem.into_problem().ok());
        Ok(OrderState {
            status,
            authorizations: self
                .authorizations
                .iter()
                .cloned()
                .map(|url| Authorization { url, state: None })
                .collect(),
            error: projected_problem,
            finalize: self.finalize.clone(),
            certificate: self.certificate.clone(),
            // Native Go does not decode the SDK ARI/profile extensions here.
            replaces: None,
            profile: None,
        })
    }
}

impl NativeAuthorization {
    pub(super) fn into_state(self) -> Result<AuthorizationState, Error> {
        let status = match self.status.as_str() {
            "pending" => AuthorizationStatus::Pending,
            "valid" => AuthorizationStatus::Valid,
            "invalid" => AuthorizationStatus::Invalid,
            "revoked" => AuthorizationStatus::Revoked,
            "expired" => AuthorizationStatus::Expired,
            "deactivated" => AuthorizationStatus::Deactivated,
            _ => return Err(native_error("unsupported native authorization status")),
        };
        Ok(AuthorizationState::go_from_parts(
            self.identifier.unwrap_or_default().into_identifier()?,
            status,
            self.challenges
                .into_iter()
                .map(NativeChallenge::into_challenge)
                .collect::<Result<_, _>>()?,
            self.wildcard.unwrap_or_default(),
        ))
    }
}

impl NativeChallenge {
    fn into_challenge(mut self) -> Result<Challenge, Error> {
        if self.url.is_empty() {
            self.url = self.uri;
        }
        let status = match self.status.as_str() {
            "" | "pending" => ChallengeStatus::Pending,
            "processing" => ChallengeStatus::Processing,
            "valid" => ChallengeStatus::Valid,
            "invalid" => ChallengeStatus::Invalid,
            _ => return Err(native_error("unsupported native challenge status")),
        };
        let kind = match self.kind.as_str() {
            "http-01" => ChallengeType::Http01,
            "dns-01" => ChallengeType::Dns01,
            "tls-alpn-01" => ChallengeType::TlsAlpn01,
            "device-attest-01" => ChallengeType::DeviceAttest01,
            _ => ChallengeType::Unknown(self.kind),
        };
        Ok(Challenge {
            r#type: kind,
            url: self.url,
            token: self.token,
            status,
            error: self.error.map(NativeProblem::into_problem).transpose()?,
        })
    }
}
