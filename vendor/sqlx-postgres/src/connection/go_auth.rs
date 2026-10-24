//! Native SCRAM behavior from pgx v5.10.0 pgconn/auth_scram.go.
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

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::signature_algorithm::RsaSsaPssParams;

use super::stream::PgStream;
use crate::error::Error;
use crate::message::{AuthenticationSasl, BackendMessageFormat, SaslInitialResponse, SaslResponse};
use crate::options::GoChannelBinding;
use crate::PgConnectOptions;

mod precis;

fn protocol(message: &'static str) -> Error {
    Error::Protocol(message.to_owned())
}

fn certificate_hash(der: &[u8]) -> Result<Vec<u8>, Error> {
    let (remaining, certificate) = X509Certificate::from_der(der)
        .map_err(|_| protocol("unable to parse channel-binding server certificate"))?;
    if !remaining.is_empty() {
        return Err(protocol("trailing channel-binding certificate data"));
    }
    if certificate.signature_algorithm != certificate.tbs_certificate.signature {
        return Err(protocol(
            "mismatched channel-binding certificate signature algorithms",
        ));
    }
    let algorithm = &certificate.signature_algorithm;
    let oid = algorithm.algorithm.to_id_string();
    let size = match oid.as_str() {
        // RFC 5929 substitutes SHA-256 for MD5 and SHA-1 signatures.
        "1.2.840.113549.1.1.4"
        | "1.2.840.113549.1.1.5"
        | "1.3.14.3.2.29"
        | "1.2.840.10045.4.1"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.10045.4.3.2" => 32,
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => 48,
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => 64,
        "1.2.840.113549.1.1.10" => {
            let parameters = algorithm
                .parameters
                .as_ref()
                .ok_or_else(|| protocol("missing channel-binding RSA-PSS parameters"))?;
            let parameters = RsaSsaPssParams::try_from(parameters)
                .map_err(|_| protocol("invalid channel-binding RSA-PSS parameters"))?;
            let hash = parameters
                .hash_algorithm()
                .ok_or_else(|| protocol("unsupported channel-binding RSA-PSS hash"))?;
            if hash
                .parameters
                .as_ref()
                .is_some_and(|value| value.as_null().is_err())
            {
                return Err(protocol("invalid channel-binding RSA-PSS hash parameters"));
            }
            let (size, suffix): (u32, u8) = match hash.algorithm.to_id_string().as_str() {
                "2.16.840.1.101.3.4.2.1" => (32, 1),
                "2.16.840.1.101.3.4.2.2" => (48, 2),
                "2.16.840.1.101.3.4.2.3" => (64, 3),
                _ => return Err(protocol("unsupported channel-binding RSA-PSS hash")),
            };
            let mgf = parameters
                .mask_gen_algorithm_raw()
                .ok_or_else(|| protocol("missing channel-binding RSA-PSS mask"))?;
            let mgf_parameters = mgf
                .parameters
                .as_ref()
                .ok_or_else(|| protocol("missing channel-binding RSA-PSS mask parameters"))?;
            // Go recognizes PSS only with MGF1 using the same SHA hash,
            // hash-sized salt, NULL/absent hash parameters and trailer=1.
            let hash_oid = [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, suffix,
            ];
            let mut hash_oid_null = hash_oid.to_vec();
            hash_oid_null.extend_from_slice(&[0x05, 0x00]);
            if mgf.algorithm.to_id_string() != "1.2.840.113549.1.1.8"
                || mgf_parameters.as_sequence().is_err()
                || !(mgf_parameters.data == hash_oid.as_slice()
                    || mgf_parameters.data == hash_oid_null.as_slice())
                || parameters.salt_length() != size
                || parameters.trailer_field() != 1
            {
                return Err(protocol("unsupported channel-binding RSA-PSS parameters"));
            }
            size
        }
        _ => {
            return Err(protocol(
                "tls-server-end-point is undefined for server certificate signature algorithm",
            ))
        }
    };
    Ok(match size {
        32 => Sha256::digest(der).to_vec(),
        48 => Sha384::digest(der).to_vec(),
        64 => Sha512::digest(der).to_vec(),
        _ => unreachable!("recognized channel-binding hash size"),
    })
}

async fn receive_auth_data(stream: &mut PgStream, expected: u32) -> Result<Vec<u8>, Error> {
    let message = stream.recv().await?;
    if message.format != BackendMessageFormat::Authentication || message.contents.len() < 4 {
        return Err(protocol("unexpected SCRAM authentication response"));
    }
    let code: [u8; 4] = message.contents[..4].try_into().map_err(Error::protocol)?;
    if u32::from_be_bytes(code) != expected {
        return Err(protocol("unexpected SCRAM authentication response"));
    }
    Ok(message.contents[4..].to_vec())
}

fn server_first(message: &[u8], nonce: &str) -> Result<(String, Vec<u8>, u32), Error> {
    let message = std::str::from_utf8(message).map_err(Error::protocol)?;
    let (nonce_value, remainder) = message
        .strip_prefix("r=")
        .and_then(|value| value.split_once(','))
        .ok_or_else(|| protocol("invalid SCRAM server-first-message: missing nonce or salt"))?;
    let (salt, iterations) = remainder
        .strip_prefix("s=")
        .and_then(|value| value.split_once(','))
        .ok_or_else(|| {
            protocol("invalid SCRAM server-first-message: missing salt or iterations")
        })?;
    let iterations = iterations
        .strip_prefix("i=")
        .ok_or_else(|| protocol("invalid SCRAM server-first-message: missing iterations"))?;
    // Go StdEncoding ignores CR/LF and accepts nonzero trailing pad bits.
    let salt: Vec<u8> = salt
        .bytes()
        .filter(|byte| !matches!(byte, b'\r' | b'\n'))
        .collect();
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    let salt = engine
        .decode(salt)
        .map_err(|_| protocol("invalid SCRAM salt"))?;
    let iterations = iterations
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0 && *value <= 10_000_000)
        .ok_or_else(|| protocol("invalid or excessive SCRAM iteration count"))?;
    if !nonce_value.starts_with(nonce) || nonce_value.len() <= nonce.len() {
        return Err(protocol("invalid SCRAM server nonce"));
    }
    let iterations =
        u32::try_from(iterations).map_err(|_| protocol("SCRAM iteration count out of range"))?;
    Ok((nonce_value.to_owned(), salt, iterations))
}

fn hmac(key: &[u8], message: &[u8]) -> Result<[u8; 32], Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(Error::protocol)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

pub(super) async fn authenticate(
    stream: &mut PgStream,
    options: &PgConnectOptions,
    data: AuthenticationSasl,
) -> Result<(), Error> {
    let go = options
        .go_compat
        .as_ref()
        .ok_or_else(|| protocol("native authentication settings are missing"))?;
    let mechanisms = data.mechanisms().collect::<Vec<_>>();
    // pgx requires the base mechanism even if PLUS is advertised.
    if !mechanisms.contains(&"SCRAM-SHA-256") {
        return Err(protocol("server does not support SCRAM-SHA-256"));
    }
    let server_has_plus = mechanisms.contains(&"SCRAM-SHA-256-PLUS");
    if go.channel_binding == GoChannelBinding::Require && !server_has_plus {
        return Err(protocol(
            "channel binding required but server does not support SCRAM-SHA-256-PLUS",
        ));
    }
    let certificate = stream.tls_peer_certificate();
    let has_tls = certificate.is_some() && go.channel_binding != GoChannelBinding::Disable;
    let binding = if has_tls {
        match certificate_hash(certificate.unwrap_or_default()) {
            Ok(hash) => Some(hash),
            Err(error) if go.channel_binding == GoChannelBinding::Require => return Err(error),
            Err(_) => None,
        }
    } else {
        None
    };
    if go.channel_binding == GoChannelBinding::Require && binding.is_none() {
        return Err(protocol(
            "channel binding required but channel binding data is not available",
        ));
    }
    let plus = server_has_plus && binding.is_some();
    let header = if plus {
        "p=tls-server-end-point,,"
    } else if has_tls {
        "y,,"
    } else {
        "n,,"
    };
    let mut random = [0; 18];
    rand::rngs::OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| protocol("unable to generate SCRAM nonce"))?;
    let nonce = STANDARD_NO_PAD.encode(random);
    let first_bare = format!("n=,r={nonce}");
    let first = format!("{header}{first_bare}");
    stream
        .send(SaslInitialResponse {
            response: &first,
            plus,
        })
        .await?;
    let server_message = receive_auth_data(stream, 11).await?;
    let (server_nonce, salt, iterations) = server_first(&server_message, &nonce)?;
    let password = precis::password(options.password.as_deref().unwrap_or_default());
    let salted = super::sasl::hi(&password, &salt, iterations)?;
    let client_key = hmac(&salted, b"Client Key")?;
    let stored_key = Sha256::digest(client_key);
    let mut channel_input = header.as_bytes().to_vec();
    if plus {
        channel_input.extend_from_slice(binding.as_deref().unwrap_or_default());
    }
    let final_bare = format!("c={},r={server_nonce}", STANDARD.encode(channel_input));
    let mut auth_message = first_bare.into_bytes();
    auth_message.push(b',');
    auth_message.extend_from_slice(&server_message);
    auth_message.push(b',');
    auth_message.extend_from_slice(final_bare.as_bytes());
    let client_signature = hmac(&stored_key, &auth_message)?;
    let proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature)
        .map(|(key, signature)| key ^ signature)
        .collect();
    let final_message = format!("{final_bare},p={}", STANDARD.encode(proof));
    stream.send(SaslResponse(&final_message)).await?;
    let server_final = receive_auth_data(stream, 12).await?;
    let verifier = server_final
        .strip_prefix(b"v=")
        .ok_or_else(|| protocol("invalid SCRAM server-final-message"))?;
    let verifier = STANDARD
        .decode(verifier)
        .map_err(|_| protocol("invalid SCRAM ServerSignature"))?;
    let server_key = hmac(&salted, b"Server Key")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&server_key).map_err(Error::protocol)?;
    mac.update(&auth_message);
    mac.verify_slice(&verifier)
        .map_err(|_| protocol("invalid SCRAM ServerSignature"))?;
    Ok(())
}
