//! Shared safe-Rust YAML boundary for configuration and upstream-shaped output.

use std::fmt;

use serde::{
    Deserialize, Serialize,
    de::{EnumAccess, IgnoredAny, MapAccess, SeqAccess, VariantAccess, Visitor},
};
use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle};

fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
        ignore_binary_tag_for_string: true,
        with_snippet: false,
        non_finite_float_policy: serde_saphyr::NonFiniteFloatPolicy::PassThrough,
    }
}

pub fn from_str<'de, T: Deserialize<'de>>(source: &'de str) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(source, options())
}

pub fn from_slice<'de, T: Deserialize<'de>>(source: &'de [u8]) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_slice_with_options(source, options())
}

pub fn to_string<T: Serialize>(value: &T) -> Result<String, serde_saphyr::SerializeError> {
    serialize(value, 2)
}

pub fn to_go_string<T: Serialize>(value: &T) -> Result<String, serde_saphyr::SerializeError> {
    let yaml = serialize(value, 4)?;
    // yaml.v3 keeps a root sequence's compact mapping at logical column 0:
    // its keys start at 2, but nested values start at 4. Saphyr accounts for
    // that compact map as a full additional level. Remove only that level.
    if yaml.starts_with("- ") {
        Ok(yaml
            .split_inclusive('\n')
            .map(|line| {
                if line.starts_with("        ") {
                    &line[4..]
                } else {
                    line
                }
            })
            .collect())
    } else {
        Ok(yaml)
    }
}

fn serialize<T: Serialize>(
    value: &T,
    indent_step: usize,
) -> Result<String, serde_saphyr::SerializeError> {
    let yaml = serde_saphyr::to_string_with_options(
        value,
        serde_saphyr::ser_options! {
            indent_step: indent_step,
            compact_list_indent: indent_step != 4,
            yaml_12: true,
            no_lang_directive: true,
            folded_wrap_chars: usize::MAX,
        },
    )?;
    // The legacy CLI uses single quotes for printable quoted scalars. Work
    // from parser spans so quotes inside block/plain scalars remain untouched.
    let mut output = String::with_capacity(yaml.len());
    let mut copied = 0;
    for next in Parser::new_from_str(&yaml) {
        let (event, span) = next.map_err(|error| serde_saphyr::SerializeError::Message {
            msg: error.to_string(),
        })?;
        if let Event::Scalar(
            text,
            style @ (ScalarStyle::DoubleQuoted | ScalarStyle::SingleQuoted),
            _,
            _,
        ) = event
            && (indent_step != 4 || !text.is_empty())
            && !text
                .chars()
                .any(|c| c.is_control() || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}'))
        {
            let plain_ipv6 = indent_step == 4
                && text.starts_with(':')
                && text.split_once('/').map_or_else(
                    || text.parse::<std::net::Ipv6Addr>().is_ok(),
                    |(address, bits)| {
                        address.parse::<std::net::Ipv6Addr>().is_ok()
                            && bits.parse::<u8>().is_ok_and(|bits| bits <= 128)
                    },
                );
            if style == ScalarStyle::SingleQuoted && !plain_ipv6 {
                continue;
            }
            let range = span
                .byte_range()
                .ok_or_else(|| serde_saphyr::SerializeError::Message {
                    msg: "serializer scalar has no byte span".into(),
                })?;
            let prefix = yaml.get(copied..range.start).ok_or_else(|| {
                serde_saphyr::SerializeError::Message {
                    msg: "serializer scalar spans are invalid".into(),
                }
            })?;
            output.push_str(prefix);
            if plain_ipv6 {
                output.push_str(&text);
            } else {
                output.push('\'');
                output.push_str(&text.replace('\'', "''"));
                output.push('\'');
            }
            copied = range.end;
        }
    }
    output.push_str(&yaml[copied..]);
    Ok(output)
}

/// Retains mapping-key presence without imposing JSON's string-key restriction.
/// Non-string/composite keys and sequences are accepted and cannot match a
/// named configuration path; scalar/null leaves still count as present.
#[derive(Debug, Default)]
pub enum Presence {
    String(String),
    Mapping(Vec<(Self, Self)>),
    Null,
    #[default]
    Other,
}

impl Presence {
    pub fn contains_path(&self, path: &[&str]) -> bool {
        let Some((first, rest)) = path.split_first() else {
            return true;
        };
        let Self::Mapping(entries) = self else {
            return false;
        };
        entries.iter().any(|(key, value)| {
            matches!(key, Self::String(key) if key == first) && value.contains_path(rest)
        })
    }

    /// Viper IsSet ignores explicit null and accepts case-insensitive keys
    /// and dotted path prefixes. Keep contains_path's literal-presence API.
    pub fn is_set_path(&self, path: &[&str]) -> bool {
        let Some((first, rest)) = path.split_first() else {
            return !matches!(self, Self::Null);
        };
        let Self::Mapping(entries) = self else {
            return false;
        };
        let dotted = path.join(".");
        for (key, value) in entries.iter().rev() {
            if matches!(key, Self::String(key) if key.eq_ignore_ascii_case(&dotted)) {
                return !matches!(value, Self::Null);
            }
        }
        entries.iter().rev().any(|(key, value)| {
            matches!(key, Self::String(key) if key.eq_ignore_ascii_case(first))
                && value.is_set_path(rest)
        })
    }
}

impl<'de> Deserialize<'de> for Presence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PresenceVisitor;
        impl<'de> Visitor<'de> for PresenceVisitor {
            type Value = Presence;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a YAML value")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Presence, E> {
                Ok(Presence::String(value.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Presence, E> {
                Ok(Presence::String(value))
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Presence, E> {
                Ok(Presence::Other)
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Presence, E> {
                Ok(Presence::Other)
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Presence, E> {
                Ok(Presence::Other)
            }
            fn visit_i128<E: serde::de::Error>(self, _: i128) -> Result<Presence, E> {
                Ok(Presence::Other)
            }
            fn visit_u128<E: serde::de::Error>(self, _: u128) -> Result<Presence, E> {
                Ok(Presence::Other)
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Presence, E> {
                Ok(Presence::Other)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Presence, E> {
                Ok(Presence::Null)
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Presence, E> {
                Ok(Presence::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Presence, A::Error> {
                while sequence.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Presence::Other)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut mapping: A) -> Result<Presence, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = mapping.next_entry()? {
                    entries.push(entry);
                }
                Ok(Presence::Mapping(entries))
            }
            fn visit_enum<A: EnumAccess<'de>>(self, value: A) -> Result<Presence, A::Error> {
                let (_, variant) = value.variant::<IgnoredAny>()?;
                let _ = variant.newtype_variant::<IgnoredAny>()?;
                Ok(Presence::Other)
            }
        }
        deserializer.deserialize_any(PresenceVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_presentation_preserves_legacy_quotes_and_roundtrips() {
        for text in [
            "",
            "true",
            "True",
            "0123",
            "null",
            "#leading",
            "a: b",
            "é: 🦀",
            "a: 'b'",
            "line\nnext",
            "line\nnext\n",
            "tab\tend",
            "nul\0end",
            "a\\b",
            "\u{85}",
            "\u{2028}",
            "\u{2029}",
        ] {
            let value = serde_json::json!({"unicode_prefix":"é🦀", "value":text});
            let yaml = to_string(&value).unwrap();
            assert_eq!(
                from_str::<serde_json::Value>(&yaml).unwrap(),
                value,
                "{yaml:?}"
            );
            let list = serde_json::json!([{
                "user": {"displayname": text}, "prefixes": ["::/0"], "empty": "",
            }]);
            let go_yaml = to_go_string(&list).unwrap();
            assert_eq!(
                from_str::<serde_json::Value>(&go_yaml).unwrap(),
                list,
                "Go-style root sequence must preserve scalar content: {go_yaml:?}"
            );
        }
        assert_eq!(
            to_string(&serde_json::json!({"error":"authentication failed: invalid token"}))
                .unwrap(),
            "error: 'authentication failed: invalid token'\n"
        );
        assert_eq!(
            to_string(&serde_json::json!({"value":""})).unwrap(),
            "value: ''\n"
        );
    }

    #[test]
    fn presence_accepts_composite_unknown_keys_and_null_leaves() {
        let tree:Presence=from_str("? [unknown, composite]\n: {nested: yes}\n? {key: value}\n: ignored\noidc:\n  strip_email_domain: null\n").unwrap();
        assert!(tree.contains_path(&["oidc", "strip_email_domain"]));
        assert!(!tree.contains_path(&["strip_email_domain"]));
        assert!(!tree.contains_path(&["oidc", "missing"]));
    }

    #[test]
    fn aliases_preserve_presence_without_applying_merge_keys() {
        let tree: Presence =
            from_str("base: &base {strip_email_domain: false}\noidc: *base\nother: {<<: *base}\n")
                .unwrap();
        assert!(tree.contains_path(&["oidc", "strip_email_domain"]));
        assert!(!tree.contains_path(&["other", "strip_email_domain"]));
        assert!(tree.contains_path(&["other", "<<", "strip_email_domain"]));
    }

    #[test]
    fn duplicate_keys_cycles_and_excessive_depth_fail_closed() {
        assert!(from_str::<Presence>("key: 1\nkey: 2\n").is_err());
        assert!(from_str::<Presence>("key: &cycle [*cycle]\n").is_err());
        let deep = format!("{}null{}", "[".repeat(300), "]".repeat(300));
        assert!(from_str::<Presence>(&deep).is_err());
    }

    #[test]
    fn yaml12_booleans_remain_strict() {
        #[derive(Deserialize)]
        struct Config {
            value: bool,
        }
        for spelling in ["true", "True", "TRUE"] {
            assert!(
                from_str::<Config>(&format!("value: {spelling}"))
                    .unwrap()
                    .value
            );
        }
        for spelling in ["false", "False", "FALSE"] {
            assert!(
                !from_str::<Config>(&format!("value: {spelling}"))
                    .unwrap()
                    .value
            );
        }
        for spelling in ["on", "off", "yes", "no", "y", "n", "1"] {
            assert!(from_str::<Config>(&format!("value: {spelling}")).is_err());
        }
    }
}
