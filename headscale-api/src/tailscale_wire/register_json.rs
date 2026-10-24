// Copyright (c) 2020, Juan Font
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
// Pinned tailcfg RegisterResponse/User/Login at headscale-go's Noise boundary.
// See UPSTREAM.md and retained upstream licenses.

//! Native registration JSON keeps the public response projection stable while
//! applying Go signed IDs, time zero omission, declaration order and escaping.

use std::io;

use serde::Serialize;

use super::{
    debug_filters::{field, json},
    go_time::DebugTime,
    wire::{RegisterResponse, SimpleLogin, SimpleUser},
};

fn typed<T: Serialize + ?Sized>(out: &mut Vec<u8>, name: &str, value: &T) -> io::Result<()> {
    field(out, name, &json(value)?)
}

pub(super) fn encode(response: &RegisterResponse) -> io::Result<Vec<u8>> {
    let mut out = vec![b'{'];
    field(&mut out, "User", &user(&response.user)?)?;
    field(&mut out, "Login", &login(&response.login)?)?;
    typed(&mut out, "NodeKeyExpired", &response.node_key_expired)?;
    typed(&mut out, "MachineAuthorized", &response.machine_authorized)?;
    typed(&mut out, "AuthURL", &response.auth_url)?;
    // This required byte-slice field has no omitempty: None emits null and
    // Some("") represents the non-nil empty byte slice's base64 encoding.
    typed(&mut out, "NodeKeySignature", &response.node_key_signature)?;
    typed(&mut out, "Error", &response.error)?;
    out.push(b'}');
    headscale_api_acl::go_json_output::compact_html(&out).map_err(io::Error::other)
}

fn user(user: &SimpleUser) -> io::Result<Vec<u8>> {
    let mut out = vec![b'{'];
    typed(&mut out, "ID", &(user.id as i64))?;
    typed(&mut out, "DisplayName", &user.display_name)?;
    if !user.profile_pic_url.is_empty() {
        typed(&mut out, "ProfilePicURL", &user.profile_pic_url)?;
    }
    if let Some(created) = &user.created {
        let created = DebugTime::decode(&json(created)?).map_err(io::Error::other)?;
        if !created.is_zero() {
            typed(
                &mut out,
                "Created",
                &created.text().map_err(io::Error::other)?,
            )?;
        }
    }
    out.push(b'}');
    Ok(out)
}

fn login(login: &SimpleLogin) -> io::Result<Vec<u8>> {
    let mut out = vec![b'{'];
    typed(&mut out, "ID", &(login.id as i64))?;
    typed(&mut out, "Provider", &login.provider)?;
    typed(&mut out, "LoginName", &login.login_name)?;
    typed(&mut out, "DisplayName", &login.display_name)?;
    if !login.profile_pic_url.is_empty() {
        typed(&mut out, "ProfilePicURL", &login.profile_pic_url)?;
    }
    out.push(b'}');
    Ok(out)
}
