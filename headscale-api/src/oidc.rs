//! OIDC helpers that mirror headscale-go's auth-provider behavior.
//!
//! The network-facing provider/callback flow is still wired separately.
//! This module keeps the pure pieces testable against upstream semantics:
//! claim authorization, issuer/subject identifiers, UserInfo merging, and
//! node-expiry selection.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize};

pub const REGISTER_METHOD_OIDC: &str = "oidc";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcPolicyConfig {
    pub allowed_domains: Vec<String>,
    pub allowed_users: Vec<String>,
    pub allowed_groups: Vec<String>,
    pub email_verified_required: bool,
    pub expiry: Duration,
    pub use_expiry_from_token: bool,
}

impl Default for OidcPolicyConfig {
    fn default() -> Self {
        Self {
            allowed_domains: Vec::new(),
            allowed_users: Vec::new(),
            allowed_groups: Vec::new(),
            email_verified_required: true,
            expiry: Duration::days(180),
            use_expiry_from_token: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcClaims {
    #[serde(default, rename = "sub")]
    pub sub: String,
    #[serde(default, rename = "iss")]
    pub iss: String,
    #[serde(default, rename = "name")]
    pub name: String,
    #[serde(default, rename = "groups")]
    pub groups: Vec<String>,
    #[serde(default, rename = "email")]
    pub email: String,
    #[serde(
        default,
        rename = "email_verified",
        deserialize_with = "deserialize_flexible_bool"
    )]
    pub email_verified: bool,
    #[serde(default, rename = "picture")]
    pub profile_picture_url: String,
    #[serde(default, rename = "preferred_username")]
    pub username: String,
}

impl OidcClaims {
    pub fn identifier(&self) -> String {
        if self.iss.is_empty() && self.sub.is_empty() {
            return String::new();
        }
        if self.iss.is_empty() {
            return clean_identifier(&self.sub);
        }
        if self.sub.is_empty() {
            return clean_identifier(&self.iss);
        }

        let issuer = self.iss.trim_end_matches('/');
        let subject = self.sub.trim_start_matches('/');
        clean_identifier(&format!("{issuer}/{subject}"))
    }

    pub fn provider_identifier(&self) -> String {
        let identifier = self.identifier();
        if self.iss.is_empty() && !identifier.starts_with('/') {
            format!("/{identifier}")
        } else {
            identifier
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcUserInfo {
    #[serde(default, rename = "sub")]
    pub sub: String,
    #[serde(default, rename = "name")]
    pub name: String,
    #[serde(default, rename = "given_name")]
    pub given_name: String,
    #[serde(default, rename = "family_name")]
    pub family_name: String,
    #[serde(default, rename = "preferred_username")]
    pub preferred_username: String,
    #[serde(default, rename = "email")]
    pub email: String,
    #[serde(
        default,
        rename = "email_verified",
        deserialize_with = "deserialize_flexible_bool"
    )]
    pub email_verified: bool,
    #[serde(default, rename = "groups")]
    pub groups: Option<Vec<String>>,
    #[serde(default, rename = "picture")]
    pub picture: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcUserProfile {
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub provider_identifier: String,
    pub provider: String,
    pub profile_pic_url: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcAuthorizationError {
    #[error("unauthorised domain")]
    UnauthorisedDomain,
    #[error("unauthorised group")]
    UnauthorisedGroup,
    #[error("unauthorised user")]
    UnauthorisedUser,
    #[error("unverified email")]
    UnverifiedEmail,
}

pub fn authorize_claims(
    cfg: &OidcPolicyConfig,
    claims: &OidcClaims,
) -> Result<(), OidcAuthorizationError> {
    if !cfg.allowed_groups.is_empty()
        && !cfg
            .allowed_groups
            .iter()
            .any(|group| claims.groups.iter().any(|claim| claim == group))
    {
        return Err(OidcAuthorizationError::UnauthorisedGroup);
    }

    let trust_email = !cfg.email_verified_required || claims.email_verified;
    let has_email_tests = !cfg.allowed_domains.is_empty() || !cfg.allowed_users.is_empty();
    if !trust_email && has_email_tests {
        return Err(OidcAuthorizationError::UnverifiedEmail);
    }

    if !cfg.allowed_domains.is_empty() {
        let Some((_, domain)) = claims.email.rsplit_once('@') else {
            return Err(OidcAuthorizationError::UnauthorisedDomain);
        };
        if !cfg.allowed_domains.iter().any(|allowed| allowed == domain) {
            return Err(OidcAuthorizationError::UnauthorisedDomain);
        }
    }

    if !cfg.allowed_users.is_empty()
        && !cfg
            .allowed_users
            .iter()
            .any(|allowed| allowed == &claims.email)
    {
        return Err(OidcAuthorizationError::UnauthorisedUser);
    }

    Ok(())
}

pub fn merge_userinfo_claims(claims: &mut OidcClaims, userinfo: Option<&OidcUserInfo>) {
    let Some(userinfo) = userinfo else {
        return;
    };
    if userinfo.sub != claims.sub {
        return;
    }

    if !userinfo.email.is_empty() {
        claims.email.clone_from(&userinfo.email);
    }
    claims.email_verified = userinfo.email_verified || claims.email_verified;
    if !userinfo.preferred_username.is_empty() {
        claims.username.clone_from(&userinfo.preferred_username);
    }
    if !userinfo.name.is_empty() {
        claims.name.clone_from(&userinfo.name);
    }
    if !userinfo.picture.is_empty() {
        claims.profile_picture_url.clone_from(&userinfo.picture);
    }
    if let Some(groups) = &userinfo.groups {
        claims.groups.clone_from(groups);
    }
}

pub fn determine_node_expiry(
    cfg: &OidcPolicyConfig,
    id_token_expiry: DateTime<Utc>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    if cfg.use_expiry_from_token {
        id_token_expiry
    } else {
        now + cfg.expiry
    }
}

pub fn user_profile_from_claims(
    claims: &OidcClaims,
    email_verified_required: bool,
) -> OidcUserProfile {
    OidcUserProfile {
        name: if is_valid_oidc_username(&claims.username) {
            claims.username.clone()
        } else {
            String::new()
        },
        display_name: claims.name.clone(),
        email: if (!email_verified_required || claims.email_verified)
            && looks_like_email_address(&claims.email)
        {
            claims.email.clone()
        } else {
            String::new()
        },
        provider_identifier: claims.provider_identifier(),
        provider: REGISTER_METHOD_OIDC.to_string(),
        profile_pic_url: claims.profile_picture_url.clone(),
    }
}

pub fn clean_identifier(identifier: &str) -> String {
    let identifier = identifier.trim();
    if identifier.is_empty() {
        return String::new();
    }

    if let Some((scheme, rest)) = identifier.split_once("://")
        && !scheme.is_empty()
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        let (authority_and_path, suffix) = split_url_suffix(rest);
        let (authority, path) = authority_and_path
            .split_once('/')
            .map_or((authority_and_path, ""), |(authority, path)| {
                (authority, path)
            });
        let path = clean_slash_path(path);
        if path.is_empty() {
            return format!("{}://{}{}", scheme.to_ascii_lowercase(), authority, suffix);
        }
        return format!(
            "{}://{}/{}{}",
            scheme.to_ascii_lowercase(),
            authority,
            path,
            suffix
        );
    }

    clean_slash_path(identifier)
}

fn split_url_suffix(rest: &str) -> (&str, &str) {
    let query = rest.find('?');
    let fragment = rest.find('#');
    let idx = match (query, fragment) {
        (Some(q), Some(f)) => q.min(f),
        (Some(q), None) => q,
        (None, Some(f)) => f,
        (None, None) => return (rest, ""),
    };
    rest.split_at(idx)
}

fn clean_slash_path(path: &str) -> String {
    path.split('/')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn is_valid_oidc_username(username: &str) -> bool {
    if username.len() < 2 {
        return false;
    }

    let Some(first) = username.chars().next() else {
        return false;
    };
    if !first.is_alphabetic() {
        return false;
    }

    let mut at_count = 0;
    for ch in username.chars() {
        match ch {
            ch if ch.is_alphabetic() || ch.is_numeric() => {}
            '-' | '.' | '_' => {}
            '@' => {
                at_count += 1;
                if at_count > 1 {
                    return false;
                }
            }
            _ => return false,
        }
    }

    true
}

fn looks_like_email_address(email: &str) -> bool {
    looks_like_simple_email_address(email)
        || email
            .split_once('<')
            .and_then(|(_, rest)| rest.split_once('>'))
            .is_some_and(|(address, trailing)| {
                trailing.trim().is_empty() && looks_like_simple_email_address(address)
            })
}

fn looks_like_simple_email_address(email: &str) -> bool {
    let email = email.trim();
    let Some((local, domain)) = email.rsplit_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !email.chars().any(char::is_whitespace)
}

fn deserialize_flexible_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum FlexibleBool {
        Bool(bool),
        String(String),
    }

    match Option::<FlexibleBool>::deserialize(deserializer)? {
        Some(FlexibleBool::Bool(value)) => Ok(value),
        Some(FlexibleBool::String(value)) => value.parse().map_err(serde::de::Error::custom),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn cfg() -> OidcPolicyConfig {
        OidcPolicyConfig {
            email_verified_required: true,
            ..OidcPolicyConfig::default()
        }
    }

    fn claims(email: &str, email_verified: bool) -> OidcClaims {
        OidcClaims {
            email: email.to_string(),
            email_verified,
            ..OidcClaims::default()
        }
    }

    #[test]
    fn oidc_authorization_matches_upstream_matrix() {
        let cases = [
            (
                "verified email domain",
                OidcPolicyConfig {
                    allowed_domains: vec!["test.com".into()],
                    ..cfg()
                },
                claims("user@test.com", true),
                Ok(()),
            ),
            (
                "verified email user",
                OidcPolicyConfig {
                    allowed_users: vec!["user@test.com".into()],
                    ..cfg()
                },
                claims("user@test.com", true),
                Ok(()),
            ),
            (
                "unverified email domain",
                OidcPolicyConfig {
                    allowed_domains: vec!["test.com".into()],
                    ..cfg()
                },
                claims("user@test.com", false),
                Err(OidcAuthorizationError::UnverifiedEmail),
            ),
            (
                "group member",
                OidcPolicyConfig {
                    allowed_groups: vec!["test".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["test".into()],
                    ..OidcClaims::default()
                },
                Ok(()),
            ),
            (
                "non group member",
                OidcPolicyConfig {
                    allowed_groups: vec!["nope".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["testo".into()],
                    ..OidcClaims::default()
                },
                Err(OidcAuthorizationError::UnauthorisedGroup),
            ),
            (
                "group member but bad domain",
                OidcPolicyConfig {
                    allowed_domains: vec!["user@good.com".into()],
                    allowed_groups: vec!["test group".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["test group".into()],
                    email: "bad@bad.com".into(),
                    email_verified: true,
                    ..OidcClaims::default()
                },
                Err(OidcAuthorizationError::UnauthorisedDomain),
            ),
            (
                "all checks pass",
                OidcPolicyConfig {
                    allowed_domains: vec!["test.com".into()],
                    allowed_users: vec!["user@test.com".into()],
                    allowed_groups: vec!["test group".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["test group".into()],
                    email: "user@test.com".into(),
                    email_verified: true,
                    ..OidcClaims::default()
                },
                Ok(()),
            ),
            (
                "all checks pass with unverified email",
                OidcPolicyConfig {
                    email_verified_required: false,
                    allowed_domains: vec!["test.com".into()],
                    allowed_users: vec!["user@test.com".into()],
                    allowed_groups: vec!["test group".into()],
                    ..OidcPolicyConfig::default()
                },
                OidcClaims {
                    groups: vec!["test group".into()],
                    email: "user@test.com".into(),
                    email_verified: false,
                    ..OidcClaims::default()
                },
                Ok(()),
            ),
            (
                "fail on unverified email",
                OidcPolicyConfig {
                    allowed_domains: vec!["test.com".into()],
                    allowed_users: vec!["user@test.com".into()],
                    allowed_groups: vec!["test group".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["test group".into()],
                    email: "user@test.com".into(),
                    email_verified: false,
                    ..OidcClaims::default()
                },
                Err(OidcAuthorizationError::UnverifiedEmail),
            ),
            (
                "unverified email user only",
                OidcPolicyConfig {
                    allowed_users: vec!["user@test.com".into()],
                    ..cfg()
                },
                claims("user@test.com", false),
                Err(OidcAuthorizationError::UnverifiedEmail),
            ),
            (
                "no filters configured",
                cfg(),
                claims("anyone@anywhere.com", false),
                Ok(()),
            ),
            (
                "multiple allowed groups second matches",
                OidcPolicyConfig {
                    allowed_groups: vec!["group1".into(), "group2".into(), "group3".into()],
                    ..cfg()
                },
                OidcClaims {
                    groups: vec!["group2".into()],
                    ..OidcClaims::default()
                },
                Ok(()),
            ),
        ];

        for (name, cfg, claims, expected) in cases {
            assert_eq!(authorize_claims(&cfg, &claims), expected, "{name}");
        }
    }

    #[test]
    fn oidc_claim_identifier_matches_headscale_go_cleanup() {
        for (input, expected) in [
            ("", ""),
            ("oidc/sub", "oidc/sub"),
            ("oidc//sub", "oidc/sub"),
            ("oidc/sub/", "oidc/sub"),
            ("oidc//sub///id//", "oidc/sub/id"),
            ("http://example.com/path", "http://example.com/path"),
            (
                "http://example.com//path///resource",
                "http://example.com/path/resource",
            ),
            ("https://example.com///path//", "https://example.com/path"),
            (
                "https://login.microsoftonline.com//v2.0/I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ",
                "https://login.microsoftonline.com/v2.0/I-70OQnj3TogrNSfkZQqB3f7dGwyBWSm1dolHNKrMzQ",
            ),
            (
                "ftp://example.com//resource//",
                "ftp://example.com/resource",
            ),
            ("///", ""),
            ("/path//to///resource", "path/to/resource"),
            (
                "ldap://example.org//path//to//resource",
                "ldap://example.org/path/to/resource",
            ),
            ("HTTPS://example.com//Path", "https://example.com/Path"),
        ] {
            assert_eq!(clean_identifier(input), expected, "{input}");
        }

        assert_eq!(
            clean_identifier("  https://issuer.example//tenant / /alice  "),
            "https://issuer.example/tenant/alice"
        );
        assert_eq!(
            clean_identifier("oidc// tenant / alice "),
            "oidc/tenant/alice"
        );
        assert_eq!(clean_identifier("///"), "");
        assert_eq!(
            OidcClaims {
                iss: "https://issuer.example/root/".into(),
                sub: "/subject".into(),
                ..OidcClaims::default()
            }
            .identifier(),
            "https://issuer.example/root/subject"
        );
        assert_eq!(
            OidcClaims {
                sub: "subject".into(),
                ..OidcClaims::default()
            }
            .provider_identifier(),
            "/subject"
        );
    }

    #[test]
    fn oidc_userinfo_merge_only_when_subject_matches() {
        let mut claims = OidcClaims {
            sub: "sub".into(),
            email: "id@example.com".into(),
            email_verified: false,
            username: "iduser".into(),
            name: "ID User".into(),
            profile_picture_url: "https://example.com/id.png".into(),
            groups: vec!["id-group".into()],
            ..OidcClaims::default()
        };

        merge_userinfo_claims(
            &mut claims,
            Some(&OidcUserInfo {
                sub: "other".into(),
                email: "ignored@example.com".into(),
                groups: Some(vec!["ignored".into()]),
                ..OidcUserInfo::default()
            }),
        );
        assert_eq!(claims.email, "id@example.com");
        assert_eq!(claims.groups, vec!["id-group"]);

        merge_userinfo_claims(
            &mut claims,
            Some(&OidcUserInfo {
                sub: "sub".into(),
                email: "user@example.com".into(),
                email_verified: true,
                preferred_username: "userinfo".into(),
                name: "User Info".into(),
                picture: "https://example.com/user.png".into(),
                groups: Some(vec!["userinfo-group".into()]),
                ..OidcUserInfo::default()
            }),
        );

        assert_eq!(claims.email, "user@example.com");
        assert!(claims.email_verified);
        assert_eq!(claims.username, "userinfo");
        assert_eq!(claims.name, "User Info");
        assert_eq!(claims.profile_picture_url, "https://example.com/user.png");
        assert_eq!(claims.groups, vec!["userinfo-group"]);
    }

    #[test]
    fn oidc_expiry_uses_token_or_config_like_upstream() {
        let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
        let token_expiry = Utc.timestamp_opt(1_700_003_600, 0).unwrap();
        let cfg = OidcPolicyConfig {
            expiry: Duration::days(180),
            ..OidcPolicyConfig::default()
        };
        assert_eq!(
            determine_node_expiry(&cfg, token_expiry, now),
            now + cfg.expiry
        );

        let cfg = OidcPolicyConfig {
            use_expiry_from_token: true,
            ..cfg
        };
        assert_eq!(determine_node_expiry(&cfg, token_expiry, now), token_expiry);
    }

    #[test]
    fn user_profile_from_claims_matches_oidc_provider_fields() {
        let profile = user_profile_from_claims(
            &OidcClaims {
                iss: "https://issuer.example".into(),
                sub: "subject".into(),
                username: "alice".into(),
                name: "Alice Smith".into(),
                email: "alice@example.com".into(),
                email_verified: true,
                profile_picture_url: "https://example.com/alice.png".into(),
                ..OidcClaims::default()
            },
            true,
        );

        assert_eq!(profile.name, "alice");
        assert_eq!(profile.display_name, "Alice Smith");
        assert_eq!(profile.email, "alice@example.com");
        assert_eq!(
            profile.provider_identifier,
            "https://issuer.example/subject"
        );
        assert_eq!(profile.provider, REGISTER_METHOD_OIDC);
        assert_eq!(profile.profile_pic_url, "https://example.com/alice.png");
    }

    #[test]
    fn user_profile_accepts_upstream_oidc_username_edges() {
        let profile = user_profile_from_claims(
            &OidcClaims {
                iss: "https://sso.company.com/oauth2/default".into(),
                sub: "00u7dr4qp7xxxxxxxxxx".into(),
                username: "tim.horton@company.com".into(),
                name: "Tim Horton".into(),
                email: "tim.horton@company.com".into(),
                email_verified: false,
                ..OidcClaims::default()
            },
            true,
        );
        assert_eq!(profile.name, "tim.horton@company.com");
        assert_eq!(profile.display_name, "Tim Horton");
        assert_eq!(profile.email, "");
        assert_eq!(
            profile.provider_identifier,
            "https://sso.company.com/oauth2/default/00u7dr4qp7xxxxxxxxxx"
        );

        let invalid = user_profile_from_claims(
            &OidcClaims {
                username: "1alice".into(),
                ..OidcClaims::default()
            },
            true,
        );
        assert_eq!(invalid.name, "");
    }

    #[test]
    fn oidc_claims_accept_flexible_email_verified_json() {
        let parsed: OidcClaims = serde_json::from_str(
            r#"{"sub":"test","email":"test@example.com","email_verified":"true"}"#,
        )
        .unwrap();
        assert_eq!(parsed.sub, "test");
        assert!(parsed.email_verified);

        let parsed: OidcClaims = serde_json::from_str(
            r#"{"sub":"test","email":"test@example.com","email_verified":"false"}"#,
        )
        .unwrap();
        assert!(!parsed.email_verified);

        let parsed: OidcClaims = serde_json::from_str(
            r#"{"sub":"test","email":"test@example.com","email_verified":true}"#,
        )
        .unwrap();
        assert!(parsed.email_verified);
    }
}
