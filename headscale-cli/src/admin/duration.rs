//! Tiny duration parser for `--expires-in` flags.
//!
//! The upstream `headscale` CLI accepts a string like `90d` / `12h` /
//! `30m` / `45s` (no fractions, single unit). We mirror that exactly —
//! pulling in `humantime` for one flag would balloon the dep tree —
//! and convert the result to whole seconds.

/// Parse a duration of the form `<integer><unit>`.
///
/// Supported units: `s` (seconds), `m` (minutes), `h` (hours),
/// `d` (days). Any other suffix, or a missing unit, is rejected. The
/// magnitude must fit in `u64` after multiplication.
///
/// `90d` ⇒ `Ok(90 * 86_400)` = 7_776_000.
pub fn parse_duration_secs(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Err("duration cannot be empty".into());
    }
    // Last char is the unit; everything before is the magnitude.
    let (num_part, unit) = s.split_at(s.len() - 1);
    let mult: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        other => {
            return Err(format!(
                "invalid duration unit '{other}'; expected one of s/m/h/d"
            ));
        }
    };
    let n: u64 = num_part
        .parse()
        .map_err(|e| format!("invalid duration magnitude '{num_part}': {e}"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("duration '{s}' overflows u64 seconds"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds() {
        assert_eq!(parse_duration_secs("30s").unwrap(), 30);
    }

    #[test]
    fn minutes() {
        assert_eq!(parse_duration_secs("5m").unwrap(), 300);
    }

    #[test]
    fn hours() {
        assert_eq!(parse_duration_secs("2h").unwrap(), 7_200);
    }

    #[test]
    fn days() {
        assert_eq!(parse_duration_secs("7d").unwrap(), 604_800);
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_duration_secs("").is_err());
    }

    #[test]
    fn rejects_no_unit() {
        assert!(parse_duration_secs("60").is_err());
    }

    #[test]
    fn rejects_bad_unit() {
        assert!(parse_duration_secs("10y").is_err());
    }

    #[test]
    fn rejects_garbage_magnitude() {
        assert!(parse_duration_secs("abc d").is_err());
    }

    #[test]
    fn rejects_overflow() {
        // 18446744073709551615 / 86400 is around 2.1e14, so this
        // overflows on multiply.
        let huge = format!("{}d", u64::MAX);
        assert!(parse_duration_secs(&huge).is_err());
    }
}
