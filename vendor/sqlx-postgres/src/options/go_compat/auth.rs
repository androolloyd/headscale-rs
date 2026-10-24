//! Pinned pgx v5.10.0 require_auth and channel_binding configuration.
//!
//! Copyright (c) 2013-2021 Jack Christensen
//!
//! MIT License
//!
//! Permission is hereby granted, free of charge, to any person obtaining
//! a copy of this software and associated documentation files (the
//! "Software"), to deal in the Software without restriction, including
//! without limitation the rights to use, copy, modify, merge, publish,
//! distribute, sublicense, and/or sell copies of the Software, and to
//! permit persons to whom the Software is furnished to do so, subject to
//! the following conditions:
//!
//! The above copyright notice and this permission notice shall be
//! included in all copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//! EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//! MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//! NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
//! LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
//! OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
//! WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use super::config_error;
use sqlx_core::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GoChannelBinding {
    Prefer,
    Disable,
    Require,
}

impl GoChannelBinding {
    pub(super) fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "" | "prefer" => Ok(Self::Prefer),
            "disable" => Ok(Self::Disable),
            "require" => Ok(Self::Require),
            _ => Err(config_error("unknown Postgres channel_binding value")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum GoAuthMethod {
    Password,
    Md5,
    Gss,
    Sspi,
    ScramSha256,
    Oauth,
    None,
}

impl GoAuthMethod {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "password" => Self::Password,
            "md5" => Self::Md5,
            "gss" => Self::Gss,
            "sspi" => Self::Sspi,
            "scram-sha-256" => Self::ScramSha256,
            "oauth" => Self::Oauth,
            "none" => Self::None,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Md5 => "md5",
            Self::Gss => "gss",
            Self::Sspi => "sspi",
            Self::ScramSha256 => "scram-sha-256",
            Self::Oauth => "oauth",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GoRequireAuth {
    raw: String,
    pub(crate) auth_required: bool,
    allowed: u8,
}

impl GoRequireAuth {
    pub(super) fn parse(value: &str) -> Result<Self, Error> {
        const ALL: u8 = (1 << 7) - 1;
        let mut policy = Self {
            raw: value.to_owned(),
            auth_required: false,
            allowed: ALL,
        };
        if value.is_empty() {
            return Ok(policy);
        }
        let mut negated = None;
        for part in value.split(',') {
            let part = part.trim();
            let (negative, name) = match part.strip_prefix('!') {
                Some(name) => (true, name),
                None => (false, part),
            };
            match negated {
                None => {
                    negated = Some(negative);
                    policy.allowed = if negative { ALL } else { 0 };
                    policy.auth_required = !negative;
                }
                Some(previous) if previous != negative => {
                    return Err(config_error(
                        "mixed positive and negative require_auth methods",
                    ));
                }
                Some(_) => {}
            }
            let method = GoAuthMethod::parse(name)
                .ok_or_else(|| config_error("invalid Postgres require_auth method"))?;
            let bit = 1_u8 << method as u8;
            if negative {
                if policy.allowed & bit == 0 {
                    return Err(config_error("duplicate Postgres require_auth method"));
                }
                policy.allowed &= !bit;
                if method == GoAuthMethod::None {
                    policy.auth_required = true;
                }
            } else {
                if policy.allowed & bit != 0 {
                    return Err(config_error("duplicate Postgres require_auth method"));
                }
                policy.allowed |= bit;
                if method == GoAuthMethod::None {
                    policy.auth_required = false;
                }
            }
        }
        Ok(policy)
    }

    pub(crate) fn check(&self, method: GoAuthMethod) -> Result<(), Error> {
        if self.allowed & (1_u8 << method as u8) != 0 {
            return Ok(());
        }
        let reason = if method == GoAuthMethod::None {
            "server did not complete authentication".to_owned()
        } else {
            format!("server requested {} authentication", method.name())
        };
        // The parser has already constrained this to method names/whitespace.
        // Quote it instead of attaching arbitrary URL/config context.
        Err(Error::Protocol(format!(
            "authentication method requirement {:?} failed: {reason}",
            self.raw
        )))
    }
}
