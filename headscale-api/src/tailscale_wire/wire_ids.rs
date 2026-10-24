// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
// Signed tailcfg IDs projected into the existing unsigned public wire fields.
// See UPSTREAM.md and LICENSE-TAILSCALE.

use std::{collections::BTreeMap, fmt};

use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};

struct Id(u64);

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IdVisitor;
        impl Visitor<'_> for IdVisitor {
            type Value = Id;

            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str("a 64-bit tailcfg ID")
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Id, E> {
                Ok(Id(value as u64))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Id, E> {
                // Preserve the public API's existing unsigned input range.
                Ok(Id(value))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Id, E> {
                Ok(Id(0))
            }
        }
        deserializer.deserialize_any(IdVisitor)
    }
}

pub(super) fn scalar<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    Id::deserialize(deserializer).map(|value| value.0)
}

pub(super) fn slice<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u64>, D::Error> {
    let ids = Option::<Vec<Option<Id>>>::deserialize(deserializer)?;
    Ok(ids
        .unwrap_or_default()
        .into_iter()
        .map(|id| id.map_or(0, |id| id.0))
        .collect())
}

pub(super) fn boolean_map<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<u64, bool>, D::Error> {
    struct IdMapVisitor;
    impl<'de> Visitor<'de> for IdMapVisitor {
        type Value = BTreeMap<u64, bool>;

        fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            out.write_str("a map of tailcfg IDs to booleans")
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(BTreeMap::new())
        }

        fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> Result<Self::Value, M::Error> {
            let mut out = BTreeMap::new();
            while let Some((name, value)) = input.next_entry::<String, Option<bool>>()? {
                let id = name
                    .parse::<u64>()
                    .or_else(|_| name.parse::<i64>().map(|id| id as u64))
                    .map_err(serde::de::Error::custom)?;
                // Convert as entries arrive so aliases retain input order.
                out.insert(id, value.unwrap_or(false));
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(IdMapVisitor)
}
