//! Table + JSON output helpers shared across admin subcommands.
//!
//! The operator gets an upstream-compatible `-o/--output` selector for
//! machine-readable formats, with a borderless fixed-width table by default.
//!
//! We deliberately don't pull in `comfy-table` / `tabled` — the output
//! is fixed across the surface and a 30-line column writer fits the
//! need.

use std::io::Write;

use serde::Serialize;
use serde_json::ser::PrettyFormatter;

use super::AdminError;

#[derive(Serialize)]
struct ErrorOutput<'a> {
    error: &'a str,
}

/// The upstream `headscale` CLI accepts an empty human-readable format
/// plus `json`, `json-line`, and `yaml` through `-o/--output`. Unknown
/// selectors fall back to human output.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    JsonLine,
    Yaml,
}

impl OutputFormat {
    pub fn from_output(output: Option<&str>) -> Result<Self, AdminError> {
        match output {
            Some("json") => Ok(Self::Json),
            Some("json-line") => Ok(Self::JsonLine),
            Some("yaml") => Ok(Self::Yaml),
            Some(_) | None => Ok(Self::Table),
        }
    }

    pub fn is_structured(self) -> bool {
        !matches!(self, Self::Table)
    }
}

/// Print `value` as pretty JSON to stdout.
pub fn print_json<T: Serialize>(value: &T) -> Result<(), AdminError> {
    let s = format_json_string(value)?;
    println!("{s}");
    Ok(())
}

fn format_json_string<T: Serialize>(value: &T) -> Result<String, AdminError> {
    let mut buf = Vec::new();
    let formatter = PrettyFormatter::with_indent(b"\t");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    value
        .serialize(&mut ser)
        .map_err(|e| AdminError::Decode(format!("serialise output: {e}")))?;
    String::from_utf8(buf).map_err(|e| AdminError::Decode(format!("serialise output: {e}")))
}

/// Print `value` in one of the upstream machine-readable formats.
pub fn print_structured<T: Serialize>(fmt: OutputFormat, value: &T) -> Result<(), AdminError> {
    match fmt {
        OutputFormat::Table => Ok(()),
        OutputFormat::Json => print_json(value),
        OutputFormat::JsonLine => {
            let s = serde_json::to_string(value)
                .map_err(|e| AdminError::Decode(format!("serialise output: {e}")))?;
            println!("{s}");
            Ok(())
        }
        OutputFormat::Yaml => {
            let s = serde_yaml::to_string(value)
                .map_err(|e| AdminError::Decode(format!("serialise output: {e}")))?;
            print!("{s}");
            Ok(())
        }
    }
}

/// Format an error exactly like upstream `headscale`'s `printError` helper.
pub fn format_error(fmt: OutputFormat, message: &str) -> String {
    let value = ErrorOutput { error: message };
    match fmt {
        OutputFormat::Table => format!("Error: {message}\n"),
        OutputFormat::Json => format_json_string(&value).map_or_else(
            |_| format!("Error: {message}\n"),
            |json| format!("{json}\n"),
        ),
        OutputFormat::JsonLine => serde_json::to_string(&value).map_or_else(
            |_| format!("Error: {message}\n"),
            |json| format!("{json}\n"),
        ),
        OutputFormat::Yaml => serde_yaml::to_string(&value).map_or_else(
            |_| format!("Error: {message}\n"),
            |yaml| format!("{yaml}\n"),
        ),
    }
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
    fn output_format_from_upstream_output_selector() {
        assert_eq!(
            OutputFormat::from_output(Some("json-line")).unwrap(),
            OutputFormat::JsonLine
        );
        assert_eq!(
            OutputFormat::from_output(Some("yaml")).unwrap(),
            OutputFormat::Yaml
        );
        assert_eq!(
            OutputFormat::from_output(None).unwrap(),
            OutputFormat::Table
        );
        assert_eq!(
            OutputFormat::from_output(Some("xml")).unwrap(),
            OutputFormat::Table
        );
    }

    #[test]
    fn formats_errors_like_upstream() {
        assert_eq!(
            format_error(OutputFormat::Table, "missing parameters"),
            "Error: missing parameters\n"
        );
        assert_eq!(
            format_error(OutputFormat::Json, "missing parameters"),
            "{\n\t\"error\": \"missing parameters\"\n}\n"
        );
        assert_eq!(
            format_error(OutputFormat::JsonLine, "missing parameters"),
            "{\"error\":\"missing parameters\"}\n"
        );
        assert_eq!(
            format_error(OutputFormat::Yaml, "missing parameters"),
            "error: missing parameters\n\n"
        );
    }

    #[test]
    fn prints_json_line_as_single_compact_line() {
        let value = serde_json::json!({"name": "alice", "id": 1});
        let s = serde_json::to_string(&value).unwrap();
        assert_eq!(s, "{\"id\":1,\"name\":\"alice\"}");
        assert!(!s.contains('\n'));
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
