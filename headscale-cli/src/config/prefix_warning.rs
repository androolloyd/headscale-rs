// BSD 3-Clause License
//
// Copyright (c) 2020, Juan Font
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Pinned v0.29.5 prefix warning, emitted after prefix/proxy validation and
//! before allocation validation. Banner text is copied from config.go's
//! warnBanner and LoadServerConfig call; CGNAT/ULA bounds follow tsaddr.
//! Source SHA-256: d27177817d7477525f78cd71fd98574aeb631bd6df39503858015c95768ea788

use std::net::IpAddr;

use crate::logging::{self, LogLevel};

pub(super) fn warn_if_nonstandard(config: &super::CliConfig, ipv4: &str, ipv6: &str) {
    let level = config
        .logging
        .as_ref()
        .map_or(1, |log| logging::configured_level(&log.level));
    if level <= 2 && (!standard_v4(ipv4) || !standard_v6(ipv6)) {
        logging::emit(
            config
                .logging
                .as_ref()
                .is_some_and(|log| log.format == "json"),
            LogLevel::Warn,
            PREFIX_WARNING,
        );
    }
}

fn standard_v4(prefix: &str) -> bool {
    let Ok((IpAddr::V4(address), length)) = super::parse_ip_prefix(prefix) else {
        return prefix.is_empty();
    };
    length >= 10 && u32::from(address) & 0xffc0_0000 == 0x6440_0000
}

fn standard_v6(prefix: &str) -> bool {
    let Ok((IpAddr::V6(address), length)) = super::parse_ip_prefix(prefix) else {
        return prefix.is_empty();
    };
    let segments = address.segments();
    length >= 48 && segments[..3] == [0xfd7a, 0x115c, 0xa1e0]
}

const PREFIX_WARNING: &str = r"
################################################################
###      __          __              _             _         ###
###      \ \        / /             (_)           | |        ###
###       \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _| |        ###
###        \ \/  \/ / _` | '__| '_ \| | '_ \ / _` | |        ###
###         \  /\  / (_| | |  | | | | | | | | (_| |_|        ###
###          \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, (_)        ###
###                                           __/ |          ###
###                                          |___/           ###
################################################################
###                                                          ###
###  You have overridden the default Headscale IP prefixes   ###
###  with a range outside of the standard CGNAT and/or ULA   ###
###  ranges. This is NOT a supported configuration.          ###
###                                                          ###
###  Using subsets of the default ranges (100.64.0.0/10 for  ###
###  IPv4, fd7a:115c:a1e0::/48 for IPv6) is fine. Using      ###
###  ranges outside of these will cause undefined behaviour  ###
###  as the Tailscale client is NOT designed to operate on   ###
###  any other ranges.                                       ###
###                                                          ###
###  Please revert your prefixes to subsets of the standard  ###
###  ranges as described in the example configuration.       ###
###                                                          ###
###  Any issue raised using a range outside of the           ###
###  supported range will be labelled as wontfix             ###
###  and closed.                                             ###
###                                                          ###
################################################################";
