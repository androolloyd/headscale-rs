//! Table + JSON output helpers shared across admin subcommands.
//!
//! The operator gets two output modes:
//!   * `--json` ⇒ raw JSON, written verbatim. Pipe into `jq` etc.
//!   * default ⇒ a borderless, fixed-width column table à la `kubectl`.
//!
//! We deliberately don't pull in `comfy-table` / `tabled` — the output
//! is fixed across the surface and a 30-line column writer fits the
//! need.

use std::io::Write;

use serde::Serialize;

use super::AdminError;

/// Whether the operator passed `--json`.
#[derive(Copy, Clone, Debug)]
pub enum OutputFormat {
    Table,
    Json,
}

impl OutputFormat {
    pub fn from_flag(json: bool) -> Self {
        if json { Self::Json } else { Self::Table }
    }
}

/// Print `value` as pretty JSON to stdout. Used by every `--json`
/// path so the format is uniform.
pub fn print_json<T: Serialize>(value: &T) -> Result<(), AdminError> {
    let s = serde_json::to_string_pretty(value)
        .map_err(|e| AdminError::Decode(format!("serialise output: {e}")))?;
    println!("{s}");
    Ok(())
}

/// Render a table of `rows` under `headers`. Each row must have the
/// same arity as `headers` — the function panics otherwise (operator
/// error in the calling code; not reachable on user input).
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut buf = std::io::stdout().lock();
    let _ = render_table_into(&mut buf, headers, rows);
}

/// Same as [`print_table`] but writes to an arbitrary sink. Exposed
/// for the unit tests that snapshot the formatted output.
pub fn render_table_into<W: Write>(
    out: &mut W,
    headers: &[&str],
    rows: &[Vec<String>],
) -> std::io::Result<()> {
    let ncols = headers.len();
    let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    for row in rows {
        assert_eq!(row.len(), ncols, "row arity must match header arity");
        for (i, cell) in row.iter().enumerate() {
            // Use the display width of the cell (chars, not bytes) so
            // non-ASCII content like the `…` ellipsis in preauth-key
            // prefixes doesn't shove the next column right.
            let w = cell.chars().count();
            if w > widths[i] {
                widths[i] = w;
            }
        }
    }
    write_row(out, headers, &widths)?;
    // A separator under the header row keeps the output legible on a
    // narrow terminal — fewer columns means the user has more room
    // for the dash run.
    let total_width: usize = widths.iter().sum::<usize>() + widths.len().saturating_sub(1) * 2;
    writeln!(out, "{}", "-".repeat(total_width))?;
    for row in rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        write_row(out, &cells, &widths)?;
    }
    Ok(())
}

fn write_row<W: Write>(out: &mut W, cells: &[&str], widths: &[usize]) -> std::io::Result<()> {
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            write!(out, "  ")?;
        }
        let chars = cell.chars().count();
        let pad = widths[i].saturating_sub(chars);
        write!(out, "{cell}{}", " ".repeat(pad))?;
    }
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_header_and_rows() {
        let mut buf: Vec<u8> = Vec::new();
        render_table_into(
            &mut buf,
            &["NAME", "AGE"],
            &[
                vec!["alice".into(), "12".into()],
                vec!["bobby".into(), "300".into()],
            ],
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        // Header present, separator present, both rows present.
        assert!(s.starts_with("NAME"));
        assert!(s.contains("---"));
        assert!(s.contains("alice"));
        assert!(s.contains("bobby"));
        // Each column is padded to its max width — `bobby` is 5 chars,
        // `NAME` is 4 chars, so the header should have at least one
        // trailing space before the gap.
        assert!(s.contains("NAME "));
    }

    #[test]
    fn empty_rows_just_print_header() {
        let mut buf: Vec<u8> = Vec::new();
        render_table_into(&mut buf, &["A", "B"], &[]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with('A'));
        assert!(s.contains("---"));
    }

    #[test]
    fn output_format_from_flag() {
        assert!(matches!(OutputFormat::from_flag(true), OutputFormat::Json));
        assert!(matches!(
            OutputFormat::from_flag(false),
            OutputFormat::Table
        ));
    }

    #[test]
    fn non_ascii_does_not_overflow() {
        // The `…` character is 3 bytes / 1 char. Width math must use
        // char count, not byte len, or the next column overshoots.
        let mut buf: Vec<u8> = Vec::new();
        render_table_into(
            &mut buf,
            &["PREFIX", "USER"],
            &[vec!["hskey-auth-aaaaaaaaaaaa-***".into(), "alice".into()]],
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("alice"));
    }
}
