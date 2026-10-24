//! Zerolog-style event output for the standalone control-plane binary.
//!
//! Keep this formatter outside the library so embedders keep their subscriber.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, IsTerminal};

use chrono::{Local, SecondsFormat};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

pub(crate) struct GoEventFormatter {
    json: bool,
    colors: bool,
}

impl GoEventFormatter {
    pub(crate) fn new(json: bool) -> Self {
        Self {
            json,
            colors: !json && console_colors(),
        }
    }
}

pub(crate) fn writer(json: bool) -> Box<dyn io::Write + Send> {
    if json {
        Box::new(io::stdout())
    } else {
        Box::new(io::stderr())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl LogLevel {
    fn parts(self) -> (&'static str, &'static str, u8, bool) {
        match self {
            Self::Trace => ("trace", "TRC", 34, false),
            Self::Debug => ("debug", "DBG", 0, false),
            Self::Info => ("info", "INF", 32, true),
            Self::Warn => ("warn", "WRN", 33, true),
            Self::Error => ("error", "ERR", 31, true),
            Self::Fatal => ("fatal", "FTL", 31, true),
        }
    }
}

/// Emit startup paths which do not have a tracing level (notably fatal).
/// The caller applies the appropriate early/configured log-level boundary.
pub(crate) fn emit(json: bool, level: LogLevel, message: &str) {
    emit_with_fields(json, level, message, &[]);
}

pub(crate) fn emit_with_fields(
    json: bool,
    level: LogLevel,
    message: &str,
    values: &[(&str, &str)],
) {
    let mut fields = Fields {
        message: message.into(),
        values: values
            .iter()
            .map(|(key, value)| ((*key).into(), LogValue::Json((*value).into())))
            .collect(),
    };
    let mut output = String::new();
    if GoEventFormatter::new(json)
        .render(&mut output, level, &mut fields)
        .is_ok()
    {
        let _ = io::Write::write_all(&mut writer(json), output.as_bytes());
    }
}

/// headscale's logConfig falls back to Debug for an invalid zerolog level.
pub(crate) fn configured_level(level: &str) -> i8 {
    // Zerolog ParseLevel uses strings.EqualFold before its numeric fallback.
    // ASCII lowercasing would turn Go's valid "diſabled" into Debug fallback,
    // enabling logs which the configured disabled level should suppress.
    [
        ("trace", -1),
        ("debug", 0),
        ("info", 1),
        ("warn", 2),
        ("error", 3),
        ("fatal", 4),
        ("panic", 5),
        ("", 6),
        ("disabled", 7),
    ]
    .into_iter()
    .find(|(name, _)| headscale_api_acl::go_unicode::equal_fold(level, name))
    .map_or_else(
        || level.parse::<i8>().unwrap_or_default(),
        |(_, level)| level,
    )
}

enum LogValue {
    Json(Value),
    Float(f64),
}

impl Serialize for LogValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Json(value) => value.serialize(serializer),
            Self::Float(value) if value.is_nan() => serializer.serialize_str("NaN"),
            Self::Float(value) if *value == f64::INFINITY => serializer.serialize_str("+Inf"),
            Self::Float(value) if *value == f64::NEG_INFINITY => serializer.serialize_str("-Inf"),
            Self::Float(value) => serde_json::value::RawValue::from_string(float(*value))
                .map_err(<S::Error as serde::ser::Error>::custom)?
                .serialize(serializer),
        }
    }
}

impl LogValue {
    fn console(self) -> String {
        let value = match self {
            Self::Float(value) if value.is_nan() => "NaN".into(),
            Self::Float(value) if value == f64::INFINITY => "+Inf".into(),
            Self::Float(value) if value == f64::NEG_INFINITY => "-Inf".into(),
            Self::Float(value) => return float(value),
            Self::Json(Value::String(value)) => value,
            Self::Json(value) => return value.to_string(),
        };
        if needs_quote(&value) {
            quote(&value)
        } else {
            value
        }
    }
}

fn float(value: f64) -> String {
    let magnitude = value.abs();
    if magnitude != 0.0 && !(1e-6..1e21).contains(&magnitude) {
        let value = format!("{value:e}");
        if let Some((mantissa, exponent)) = value.split_once('e')
            && let Ok(exponent) = exponent.parse::<i32>()
        {
            return format!("{mantissa}e{exponent:+}");
        }
        value
    } else {
        value.to_string()
    }
}

#[derive(Default)]
struct Fields {
    message: String,
    values: Vec<(String, LogValue)>,
}

impl Fields {
    fn insert(&mut self, field: &Field, value: Value) {
        if field.name() == "message" {
            self.message = match value {
                Value::String(value) => value,
                value => value.to_string(),
            };
        } else {
            self.values
                .push((field.name().to_string(), LogValue::Json(value)));
        }
    }
}

impl Visit for Fields {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, value.into());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, value.into());
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        if field.name() == "message" {
            self.message = float(value);
        } else {
            self.values
                .push((field.name().into(), LogValue::Float(value)));
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, value.into());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert(field, format!("{value:?}").into());
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, value.to_string().into());
    }
}

struct JsonEvent<'a> {
    level: &'a str,
    fields: &'a Fields,
    time: i64,
}

impl Serialize for JsonEvent<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Zerolog writes the level, event fields, timestamp hook, then message.
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("level", self.level)?;
        for (name, value) in &self.fields.values {
            map.serialize_entry(name, value)?;
        }
        map.serialize_entry("time", &self.time)?;
        if !self.fields.message.is_empty() {
            map.serialize_entry("message", &self.fields.message)?;
        }
        map.end()
    }
}

impl<S, N> FormatEvent<S, N> for GoEventFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        context: &FmtContext<'_, S, N>,
        mut output: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = Fields::default();
        // Preserve useful tracing span context without inserting Rust targets
        // or source paths into every otherwise Go-shaped log record.
        if let Some(scope) = context.event_scope() {
            let spans = scope
                .from_root()
                .map(|span| {
                    let extensions = span.extensions();
                    let fields = extensions.get::<FormattedFields<N>>();
                    fields.map_or_else(
                        || span.name().to_string(),
                        |fields| format!("{}{{{fields}}}", span.name()),
                    )
                })
                .collect::<Vec<_>>();
            if !spans.is_empty() {
                fields
                    .values
                    .push(("span".into(), LogValue::Json(spans.join(" ").into())));
            }
        }
        event.record(&mut fields);
        let level = match *event.metadata().level() {
            Level::TRACE => LogLevel::Trace,
            Level::DEBUG => LogLevel::Debug,
            Level::INFO => LogLevel::Info,
            Level::WARN => LogLevel::Warn,
            _ => LogLevel::Error,
        };
        self.render(&mut output, level, &mut fields)
    }
}

impl GoEventFormatter {
    fn render(
        &self,
        mut output: impl fmt::Write,
        level: LogLevel,
        fields: &mut Fields,
    ) -> fmt::Result {
        let now = Local::now();
        let (name, short, color, bold) = level.parts();
        if self.json {
            let event = JsonEvent {
                level: name,
                fields,
                time: now.timestamp(),
            };
            let json = serde_json::to_string(&event).map_err(|_| fmt::Error)?;
            return writeln!(output, "{json}");
        }
        let timestamp = now.to_rfc3339_opts(SecondsFormat::Secs, true);
        // Zerolog's console consumes a JSON object, so duplicate field names
        // keep their last value. Raw JSON output above retains event order.
        let mut values: BTreeMap<_, _> = std::mem::take(&mut fields.values).into_iter().collect();
        let _ = values.remove("time");
        let _ = values.remove("level");
        self.part(&mut output, &timestamp, 90)?;
        output.write_char(' ')?;
        self.part(&mut output, short, color)?;
        if let Some(LogValue::Json(Value::String(caller))) = values.remove("caller")
            && !caller.is_empty()
        {
            output.write_char(' ')?;
            self.part(&mut output, &relative_caller(&caller), 1)?;
            self.part(&mut output, " >", 36)?;
        }
        if !fields.message.is_empty() {
            output.write_char(' ')?;
            self.part(&mut output, &fields.message, u8::from(bold))?;
        }
        let error = values.remove_entry("error");
        for (key, value) in error.into_iter().chain(values) {
            output.write_char(' ')?;
            self.part(&mut output, &format!("{key}="), 36)?;
            let value = value.console();
            if key == "error" && self.colors {
                write!(output, "\x1b[31m\x1b[1m{value}\x1b[0m\x1b[0m")?;
            } else {
                output.write_str(&value)?;
            }
        }
        writeln!(output)
    }
    fn part(&self, output: &mut impl fmt::Write, value: &str, color: u8) -> fmt::Result {
        if self.colors && color != 0 {
            write!(output, "\x1b[{color}m{value}\x1b[0m")
        } else {
            output.write_str(value)
        }
    }
}

/// Boolean color support from pinned termcolor v1.0.2 on Unix. Headscale's
/// presence-based NO_COLOR override applies after that library's decision.
fn console_colors() -> bool {
    use std::ffi::OsStr;
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    let args = std::env::args_os()
        .take_while(|arg| arg != OsStr::new("--"))
        .collect::<Vec<_>>();
    let flag = |name: &str| args.iter().any(|arg| arg == OsStr::new(name));
    if [
        "--no-color",
        "--no-colors",
        "--color=false",
        "--color=never",
    ]
    .iter()
    .any(|name| flag(name))
    {
        return false;
    }
    if [
        "--color=16m",
        "--color=full",
        "--color=truecolor",
        "--color=256",
    ]
    .iter()
    .any(|name| flag(name))
    {
        return true;
    }
    let force = std::env::var_os("FORCE_COLOR");
    if !io::stderr().is_terminal() && force.is_none() {
        return false;
    }
    let minimum = if let Some(force) = force {
        match force.to_string_lossy().as_ref() {
            "true" => true,
            "false" => false,
            value => !matches!(value.parse::<isize>(), Ok(0)),
        }
    } else {
        ["--color", "--colors", "--color=true", "--color=always"]
            .iter()
            .any(|name| flag(name))
    };
    let env = |name: &str| std::env::var(name).unwrap_or_default();
    let term = env("TERM");
    if term == "dumb" {
        return minimum;
    }
    if std::env::var_os("TEAMCITY_VERSION").is_some() {
        let version = env("TEAMCITY_VERSION");
        return version.split_once('.').is_some_and(|(major, rest)| {
            (major.len() >= 2 && major.bytes().all(|byte| byte.is_ascii_digit()))
                || (major == "9"
                    && rest.split_once('.').is_some_and(|(minor, _)| {
                        !minor.is_empty()
                            && minor.bytes().all(|byte| byte.is_ascii_digit())
                            && minor.bytes().any(|byte| byte != b'0')
                    }))
        });
    }
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        return true;
    }
    if std::env::var_os("CI").is_some() {
        return ["TRAVIS", "CIRCLECI", "APPVEYOR", "GITLAB_CI"]
            .iter()
            .any(|name| std::env::var_os(name).is_some())
            || env("CI_NAME") == "codeship"
            || minimum;
    }
    if env("COLORTERM") == "truecolor" {
        return true;
    }
    if matches!(env("TERM_PROGRAM").as_str(), "iTerm.app" | "Apple_Terminal") {
        return true;
    }
    ["screen", "xterm", "vt100", "vt220", "rxvt"]
        .iter()
        .any(|prefix| term.starts_with(prefix))
        || ["color", "ansi", "cygwin", "linux"]
            .iter()
            .any(|part| term.contains(part))
        || std::env::var_os("COLORTERM").is_some()
        || minimum
}

fn relative_caller(caller: &str) -> String {
    use std::path::{Component, Path, PathBuf};
    let path = Path::new(caller);
    if !path.is_absolute() {
        return caller.into();
    }
    let Ok(cwd) = std::env::current_dir() else {
        return caller.into();
    };
    let source = cwd.components().collect::<Vec<_>>();
    let destination = path.components().collect::<Vec<_>>();
    let common = source
        .iter()
        .zip(&destination)
        .take_while(|(a, b)| a == b)
        .count();
    if common == 0 {
        return caller.into();
    }
    let mut relative = PathBuf::new();
    for component in &source[common..] {
        if matches!(component, Component::Normal(_)) {
            relative.push("..");
        }
    }
    for component in &destination[common..] {
        relative.push(component.as_os_str());
    }
    if relative.as_os_str().is_empty() {
        ".".into()
    } else {
        relative.to_string_lossy().into_owned()
    }
}

fn needs_quote(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| !(0x21..=0x7e).contains(&byte) || matches!(byte, b'\\' | b'"'))
}

pub(crate) fn quote(value: &str) -> String {
    headscale_api_acl::go_strconv::quote(value)
}
