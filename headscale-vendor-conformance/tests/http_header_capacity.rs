//! Conformance test for the `go-native-header-capacity` feature of the patched
//! `http` crate (`vendor/http`, enabled workspace-wide by instant-acme's
//! `go-native-client`).
//!
//! Stock `http::HeaderMap` addresses its table with `u16` indices and caps the
//! raw table at `1 << 15` slots (fewer usable entries once the load factor is
//! applied), so inserting this many distinct fields fails with `MaxSizeReached`. With the feature, indices and hashes are `u32` and the cap
//! is `1 << 22`. Go's `http.Header` is an unbounded map, so a response carrying
//! tens of thousands of fields (limited only by the separate byte limits of the
//! native admission path) must still be representable.
//!
//! The feature is a compile-time switch (cargo feature unification applies it
//! to every user of `http` in the build), so stock-versus-native cannot be
//! compared inside one binary: against the pristine crate this test does not
//! compile, and against the crate with the feature off it fails with
//! `MaxSizeReached` before the table reaches `1 << 15` fields.
//!
//! Go: `net/http.Header` (`map[string][]string`), no field-count limit;
//! `vendor/http/UPSTREAM.md` ("Selected http source and native header
//! capacity").

use http::header::{HeaderMap, HeaderName, HeaderValue};

/// Comfortably above the stock raw-table capacity (`1 << 15`).
const BEYOND_STOCK_CAPACITY: usize = (1 << 15) + 1_000;

#[test]
fn header_map_holds_more_distinct_fields_than_the_stock_table_allows() {
    let mut map = HeaderMap::new();
    for index in 0..BEYOND_STOCK_CAPACITY {
        let name = HeaderName::from_bytes(format!("x-field-{index}").as_bytes())
            .expect("valid header name");
        let appended = map
            .try_append(name, HeaderValue::from_static("1"))
            .unwrap_or_else(|_| panic!("table full at {index} fields; stock cap is {}", 1 << 15));
        assert!(!appended, "each name is new, so no value is replaced");
    }
    assert_eq!(map.len(), BEYOND_STOCK_CAPACITY);

    // Lookups past the old index width still resolve (u32 hashes/indices).
    for index in [0, (1 << 15) - 1, 1 << 15, BEYOND_STOCK_CAPACITY - 1] {
        let name = format!("x-field-{index}");
        assert_eq!(
            map.get(name.as_str()).map(HeaderValue::as_bytes),
            Some(&b"1"[..]),
            "field {index}"
        );
    }
}
