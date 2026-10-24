use atoi::atoi;
use memchr::memrchr;
use sqlx_core::bytes::Bytes;

use crate::error::Error;
use crate::message::{BackendMessage, BackendMessageFormat};

#[derive(Debug)]
pub struct CommandComplete {
    /// The command tag. This is usually a single word that identifies which SQL command
    /// was completed.
    tag: Bytes,
}

impl BackendMessage for CommandComplete {
    const FORMAT: BackendMessageFormat = BackendMessageFormat::CommandComplete;

    fn decode_body(bytes: Bytes) -> Result<Self, Error> {
        Ok(CommandComplete { tag: bytes })
    }
}

impl CommandComplete {
    /// pgproto3 requires the first NUL to be the final payload byte.
    /// Generic SQLx decoding retains its existing framing behavior.
    pub(crate) fn validate_go(&self) -> Result<(), Error> {
        match self.tag.iter().position(|&byte| byte == 0) {
            None => Err(err_protocol!(
                "CommandComplete body is invalid unterminated string"
            )),
            Some(index) if index != self.tag.len() - 1 => Err(err_protocol!(
                "CommandComplete body is invalid string terminated too early"
            )),
            Some(_) => Ok(()),
        }
    }

    /// Native pgx CommandTag scans the trailing decimal run with signed-int64
    /// wrapping, without requiring a separating space. SQLx exposes row counts
    /// as u64; retain those bits at that existing public result boundary.
    /// Adapted from pgx v5.10.0 pgconn.go (LICENSE-GO-PGX).
    pub(crate) fn go_rows_affected(&self) -> u64 {
        let tag = self.tag.strip_suffix(&[0]).unwrap_or(&self.tag);
        let mut count = 0u64;
        let mut multiplier = 1u64;
        for &byte in tag.iter().rev() {
            if !byte.is_ascii_digit() {
                break;
            }
            count = count.wrapping_add(u64::from(byte - b'0').wrapping_mul(multiplier));
            multiplier = multiplier.wrapping_mul(10);
        }
        count
    }

    /// Returns the number of rows affected.
    /// If the command does not return rows (e.g., "CREATE TABLE"), returns 0.
    pub fn rows_affected(&self) -> u64 {
        // Look backwards for the first SPACE
        memrchr(b' ', &self.tag)
            // This is either a word or the number of rows affected
            .and_then(|i| atoi(&self.tag[(i + 1)..]))
            .unwrap_or(0)
    }
}

#[test]
fn test_decode_command_complete_for_insert() {
    const DATA: &[u8] = b"INSERT 0 1214\0";

    let cc = CommandComplete::decode_body(Bytes::from_static(DATA)).unwrap();

    assert_eq!(cc.rows_affected(), 1214);
}

#[test]
fn test_decode_command_complete_for_begin() {
    const DATA: &[u8] = b"BEGIN\0";

    let cc = CommandComplete::decode_body(Bytes::from_static(DATA)).unwrap();

    assert_eq!(cc.rows_affected(), 0);
}

#[test]
fn test_decode_command_complete_for_update() {
    const DATA: &[u8] = b"UPDATE 5\0";

    let cc = CommandComplete::decode_body(Bytes::from_static(DATA)).unwrap();

    assert_eq!(cc.rows_affected(), 5);
}

#[cfg(all(test, not(debug_assertions)))]
#[bench]
fn bench_decode_command_complete(b: &mut test::Bencher) {
    const DATA: &[u8] = b"INSERT 0 1214\0";

    b.iter(|| {
        let _ = CommandComplete::decode_body(test::black_box(Bytes::from_static(DATA)));
    });
}

#[cfg(all(test, not(debug_assertions)))]
#[bench]
fn bench_decode_command_complete_rows_affected(b: &mut test::Bencher) {
    const DATA: &[u8] = b"INSERT 0 1214\0";

    let data = CommandComplete::decode_body(Bytes::from_static(DATA)).unwrap();

    b.iter(|| {
        let _rows = test::black_box(&data).rows_affected();
    });
}
