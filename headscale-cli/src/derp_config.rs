//! DERP source loading for upstream-shaped `derp:` config.
//!
//! Startup loading can fetch JSON URL maps and merge local YAML path maps into
//! the wire `DerpMap`. Config validation uses the same local path-map parser
//! without fetching URLs; the CLI server owns the periodic auto-update worker.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use crc::{CRC_64_GO_ISO, Crc};
use headscale_api::tailscale_wire::{DerpMap, DerpRegion, DerpRegionNode};
use serde::{Deserialize, Serialize};

const DERP_MAP_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct DerpConfig {
    /// Embedded DERP server settings from upstream headscale v0.28.
    pub server: UpstreamDerpServerConfig,
    /// Externally available DERP maps encoded as JSON.
    pub urls: Vec<String>,
    /// Local DERP map files encoded as YAML.
    pub paths: Vec<PathBuf>,
    /// When true and `update_frequency` is non-zero, refresh DERP sources at
    /// runtime.
    pub auto_update_enabled: bool,
    /// Runtime refresh period in seconds.
    #[serde(deserialize_with = "crate::config::deserialize_duration_secs_from_int_or_string")]
    pub update_frequency: u64,
}

impl Default for DerpConfig {
    fn default() -> Self {
        Self {
            server: UpstreamDerpServerConfig::default(),
            urls: Vec::new(),
            paths: Vec::new(),
            auto_update_enabled: false,
            update_frequency: 3 * 60 * 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct UpstreamDerpServerConfig {
    pub enabled: bool,
    pub region_id: u16,
    pub region_code: String,
    pub region_name: String,
    pub verify_clients: bool,
    pub stun_listen_addr: Option<std::net::SocketAddr>,
    pub private_key_path: PathBuf,
    pub automatically_add_embedded_derp_region: bool,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

impl Default for UpstreamDerpServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            region_id: 999,
            region_code: "headscale".to_string(),
            region_name: "Headscale Embedded DERP".to_string(),
            verify_clients: true,
            stun_listen_addr: Some("0.0.0.0:3478".parse().unwrap()),
            private_key_path: PathBuf::from("/var/lib/headscale/derp_server_private.key"),
            automatically_add_embedded_derp_region: true,
            ipv4: None,
            ipv6: None,
        }
    }
}

/// URL fixture map used by tests and offline callers. Keys are `derp.urls`
/// entries and values are JSON DERP map bytes.
pub(crate) type UrlFixtureMap = BTreeMap<String, Vec<u8>>;

pub(crate) fn load_static_derp_map(
    config: &DerpConfig,
    url_fixtures: &UrlFixtureMap,
) -> Result<DerpMap> {
    let mut map = DerpMap::default();

    for url in &config.urls {
        let Some(bytes) = url_fixtures.get(url) else {
            continue;
        };
        let source: SourceDerpMap = serde_json::from_slice(bytes)
            .with_context(|| format!("parse DERP JSON fixture for {url}"))?;
        merge_derp_regions(&mut map, source);
    }

    for path in &config.paths {
        let source = load_derp_path_map(path)?;
        apply_path_map(&mut map, source)
            .with_context(|| format!("apply DERP YAML path map {}", path.display()))?;
    }

    Ok(map)
}

pub(crate) fn validate_static_derp_config(config: &DerpConfig) -> Result<()> {
    validate_derp_flags(config)?;

    let fixtures = UrlFixtureMap::default();
    load_static_derp_map(config, &fixtures).map(|_| ())
}

fn validate_derp_flags(config: &DerpConfig) -> Result<()> {
    if config.server.enabled && config.server.stun_listen_addr.is_none() {
        bail!("derp.server.stun_listen_addr is required when derp.server.enabled=true");
    }

    if config.server.enabled
        && !config.server.automatically_add_embedded_derp_region
        && config.paths.is_empty()
    {
        bail!(
            "derp.server.automatically_add_embedded_derp_region=false requires at least one derp.paths entry"
        );
    }

    Ok(())
}

pub(crate) async fn load_derp_map(config: &DerpConfig, base_domain: &str) -> Result<DerpMap> {
    validate_derp_flags(config)?;

    let mut map = DerpMap::default();
    let client = reqwest::Client::builder()
        .timeout(DERP_MAP_FETCH_TIMEOUT)
        .build()
        .context("build DERP JSON map HTTP client")?;

    for url in &config.urls {
        let response = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("fetch DERP JSON map {url}"))?
            .error_for_status()
            .with_context(|| format!("fetch DERP JSON map {url}"))?;
        let bytes = response
            .bytes()
            .await
            .with_context(|| format!("read DERP JSON map {url}"))?;
        let source: SourceDerpMap =
            serde_json::from_slice(&bytes).with_context(|| format!("parse DERP JSON map {url}"))?;
        merge_derp_regions(&mut map, source);
    }

    for path in &config.paths {
        let source = load_derp_path_map(path)?;
        apply_path_map(&mut map, source)
            .with_context(|| format!("apply DERP YAML path map {}", path.display()))?;
    }

    shuffle_derp_map(&mut map, base_domain);

    Ok(map)
}

fn load_derp_path_map(path: &Path) -> Result<DerpPathMap> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read DERP YAML path map {}", path.display()))?;
    serde_yaml::from_str(&contents)
        .with_context(|| format!("parse DERP YAML path map {}", path.display()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SourceDerpMap {
    #[serde(default)]
    regions: HashMap<u16, Option<DerpRegion>>,
}

fn merge_derp_regions(dest: &mut DerpMap, source: SourceDerpMap) {
    for (region_id, region) in source.regions {
        match region {
            Some(region) => {
                dest.regions.insert(region_id, region);
            }
            None => {
                dest.regions.remove(&region_id);
            }
        }
    }
}

pub(crate) fn shuffle_derp_map(map: &mut DerpMap, base_domain: &str) {
    if map.regions.is_empty() {
        return;
    }

    with_derp_random(base_domain, |rng| shuffle_derp_map_with_rng(map, rng));
}

fn shuffle_derp_map_with_rng(map: &mut DerpMap, rng: &mut GoMathRand) {
    let mut region_ids = map.regions.keys().copied().collect::<Vec<_>>();
    region_ids.sort_unstable();

    for region_id in region_ids {
        let Some(region) = map.regions.get_mut(&region_id) else {
            continue;
        };
        shuffle_slice(&mut region.nodes, rng);
    }
}

#[cfg(test)]
fn shuffle_derp_map_with_seed(map: &mut DerpMap, base_domain: &str) {
    let mut rng = GoMathRand::new(derp_random_seed(base_domain));
    shuffle_derp_map_with_rng(map, &mut rng);
}

fn shuffle_slice<T>(items: &mut [T], rng: &mut GoMathRand) {
    if items.len() < 2 {
        return;
    }

    let mut i = items.len() - 1;
    while i > (i32::MAX as usize - 1) {
        let j = usize::try_from(rng.int63n(i64::try_from(i + 1).unwrap())).unwrap();
        items.swap(i, j);
        i -= 1;
    }
    while i > 0 {
        let j = usize::try_from(rng.int31n_fast(i32::try_from(i + 1).unwrap())).unwrap();
        items.swap(i, j);
        i -= 1;
    }
}

static DERP_RANDOM: OnceLock<Mutex<Option<GoMathRand>>> = OnceLock::new();

fn with_derp_random<T>(base_domain: &str, f: impl FnOnce(&mut GoMathRand) -> T) -> T {
    let mut guard = DERP_RANDOM
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.is_none() {
        *guard = Some(GoMathRand::new(derp_random_seed(base_domain)));
    }
    f(guard
        .as_mut()
        .expect("DERP random source is initialized above"))
}

fn derp_random_seed(base_domain: &str) -> i64 {
    const CRC64_GO_ISO: Crc<u64> = Crc::<u64>::new(&CRC_64_GO_ISO);

    let fallback;
    let seed = if base_domain.is_empty() {
        fallback = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or_else(
                |err| format!("{err:?}"),
                |duration| duration.as_nanos().to_string(),
            );
        fallback.as_str()
    } else {
        base_domain
    };

    CRC64_GO_ISO.checksum(seed.as_bytes()) as i64
}

struct GoMathRand {
    tap: usize,
    feed: usize,
    vec: [i64; RNG_LEN],
}

impl GoMathRand {
    fn new(seed: i64) -> Self {
        let mut rng = Self {
            tap: 0,
            feed: 0,
            vec: [0; RNG_LEN],
        };
        rng.seed(seed);
        rng
    }

    fn seed(&mut self, seed: i64) {
        self.tap = 0;
        self.feed = RNG_LEN - RNG_TAP;

        let mut seed = seed % i64::from(I32_MAX);
        if seed < 0 {
            seed += i64::from(I32_MAX);
        }
        if seed == 0 {
            seed = 89_482_311;
        }

        let cooked = rng_cooked();
        let mut x = i32::try_from(seed).expect("math/rand seed is below i32::MAX");
        for i in -20..isize::try_from(RNG_LEN).unwrap() {
            x = seedrand(x);
            if i >= 0 {
                let mut u = i64::from(x).wrapping_shl(40);
                x = seedrand(x);
                u ^= i64::from(x).wrapping_shl(20);
                x = seedrand(x);
                u ^= i64::from(x);
                u ^= cooked[usize::try_from(i).unwrap()];
                self.vec[usize::try_from(i).unwrap()] = u;
            }
        }
    }

    fn uint64(&mut self) -> u64 {
        if self.tap == 0 {
            self.tap += RNG_LEN;
        }
        self.tap -= 1;

        if self.feed == 0 {
            self.feed += RNG_LEN;
        }
        self.feed -= 1;

        let x = self.vec[self.feed].wrapping_add(self.vec[self.tap]);
        self.vec[self.feed] = x;
        x as u64
    }

    fn int63(&mut self) -> i64 {
        (self.uint64() & RNG_MASK) as i64
    }

    fn uint32(&mut self) -> u32 {
        (self.int63() >> 31) as u32
    }

    fn int63n(&mut self, n: i64) -> i64 {
        assert!(n > 0, "invalid argument to Int63n");
        if n & (n - 1) == 0 {
            return self.int63() & (n - 1);
        }
        let max = (i64::MAX as u64 - ((1_u64 << 63) % (n as u64))) as i64;
        let mut v = self.int63();
        while v > max {
            v = self.int63();
        }
        v % n
    }

    fn int31n_fast(&mut self, n: i32) -> i32 {
        let mut v = self.uint32();
        let mut prod = u64::from(v) * u64::from(n as u32);
        let mut low = prod as u32;
        if low < n as u32 {
            let thresh = 0_u32.wrapping_sub(n as u32) % n as u32;
            while low < thresh {
                v = self.uint32();
                prod = u64::from(v) * u64::from(n as u32);
                low = prod as u32;
            }
        }
        (prod >> 32) as i32
    }
}

fn seedrand(x: i32) -> i32 {
    const A: i32 = 48271;
    const Q: i32 = 44488;
    const R: i32 = 3399;

    let hi = x / Q;
    let lo = x % Q;
    let x = A * lo - R * hi;
    if x < 0 { x + I32_MAX } else { x }
}

fn rng_cooked() -> &'static [i64; RNG_LEN] {
    static COOKED: OnceLock<[i64; RNG_LEN]> = OnceLock::new();

    COOKED.get_or_init(|| {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(RNG_COOKED_LE_BASE64)
            .expect("embedded Go math/rand rngCooked table decodes");
        assert_eq!(raw.len(), RNG_LEN * std::mem::size_of::<i64>());

        let mut cooked = [0_i64; RNG_LEN];
        for (idx, chunk) in raw.chunks_exact(std::mem::size_of::<i64>()).enumerate() {
            cooked[idx] = i64::from_le_bytes(chunk.try_into().unwrap());
        }
        cooked
    })
}

const RNG_LEN: usize = 607;
const RNG_TAP: usize = 273;
const RNG_MASK: u64 = (1_u64 << 63) - 1;
const I32_MAX: i32 = i32::MAX;
const RNG_COOKED_LE_BASE64: &str = concat!(
    "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",
);

fn apply_path_map(dest: &mut DerpMap, source: DerpPathMap) -> Result<()> {
    for (region_id, region) in source.regions {
        match region {
            None => {
                dest.regions.remove(&region_id);
            }
            Some(region) => {
                let region = region.into_wire(region_id)?;
                dest.regions.insert(region_id, region);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct DerpPathMap {
    #[serde(default)]
    regions: BTreeMap<u16, Option<PathDerpRegion>>,
}

#[derive(Debug, Deserialize)]
struct PathDerpRegion {
    #[serde(alias = "RegionID", alias = "regionID")]
    regionid: Option<u16>,
    #[serde(default, alias = "RegionCode", alias = "regionCode")]
    regioncode: String,
    #[serde(default, alias = "RegionName", alias = "regionName")]
    regionname: String,
    #[serde(default, alias = "Latitude")]
    latitude: f64,
    #[serde(default, alias = "Longitude")]
    longitude: f64,
    #[serde(default, alias = "Avoid")]
    avoid: bool,
    #[serde(default, alias = "NoMeasureNoHome", alias = "noMeasureNoHome")]
    no_measure_no_home: bool,
    #[serde(default, alias = "Nodes")]
    nodes: Vec<PathDerpNode>,
}

impl PathDerpRegion {
    fn into_wire(self, map_region_id: u16) -> Result<DerpRegion> {
        let region_id = self.regionid.unwrap_or(map_region_id);
        if region_id != map_region_id {
            bail!("DERP region key {map_region_id} does not match regionid {region_id}");
        }
        let mut nodes = Vec::with_capacity(self.nodes.len());
        for node in self.nodes {
            nodes.push(node.into_wire(region_id)?);
        }
        Ok(DerpRegion {
            region_id,
            region_code: self.regioncode,
            region_name: self.regionname,
            latitude: self.latitude,
            longitude: self.longitude,
            avoid: self.avoid,
            no_measure_no_home: self.no_measure_no_home,
            nodes,
        })
    }
}

#[derive(Debug, Deserialize)]
struct PathDerpNode {
    #[serde(alias = "Name")]
    name: String,
    #[serde(alias = "RegionID", alias = "regionID")]
    regionid: Option<u16>,
    #[serde(alias = "HostName", alias = "hostname")]
    hostname: String,
    #[serde(default, alias = "CertName", alias = "certName")]
    certname: String,
    #[serde(default, alias = "IPv4", alias = "ipv4")]
    ipv4: String,
    #[serde(default, alias = "IPv6", alias = "ipv6")]
    ipv6: String,
    #[serde(default, alias = "DERPPort", alias = "derpPort")]
    derpport: u16,
    #[serde(default, alias = "STUNPort", alias = "stunPort")]
    stunport: i32,
    #[serde(default, alias = "STUNOnly", alias = "stunOnly")]
    stunonly: bool,
    #[serde(default, alias = "InsecureForTests", alias = "insecureForTests")]
    insecure_for_tests: bool,
    #[serde(default, alias = "STUNTestIP", alias = "stunTestIP")]
    stun_test_ip: String,
    #[serde(default, alias = "CanPort80", alias = "canPort80")]
    canport80: bool,
}

impl PathDerpNode {
    fn into_wire(self, fallback_region_id: u16) -> Result<DerpRegionNode> {
        let region_id = self.regionid.unwrap_or(fallback_region_id);
        if region_id != fallback_region_id {
            bail!(
                "DERP node {} regionid {region_id} does not match region {fallback_region_id}",
                self.name
            );
        }
        Ok(DerpRegionNode {
            name: self.name,
            region_id,
            host_name: self.hostname,
            cert_name: self.certname,
            ipv4: self.ipv4,
            ipv6: self.ipv6,
            derp_port: self.derpport,
            stun_port: self.stunport,
            stun_only: self.stunonly,
            insecure_for_tests: self.insecure_for_tests,
            stun_test_ip: self.stun_test_ip,
            can_port80: self.canport80,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use httpmock::Method::GET;

    #[test]
    fn loads_json_url_fixture_and_yaml_path_override() {
        let mut fixtures = UrlFixtureMap::new();
        fixtures.insert(
            "https://derp.example/map.json".to_string(),
            serde_json::to_vec(&serde_json::json!({
                "omitDefaultRegions": true,
                "HomeParams": {
                    "RegionScore": {
                        "1": 0.5
                    }
                },
                "Regions": {
                    "1": {
                        "RegionID": 1,
                        "RegionCode": "default",
                        "RegionName": "Default",
                        "Nodes": [{
                            "Name": "1a",
                            "RegionID": 1,
                            "HostName": "derp1.example.com"
                        }]
                    }
                }
            }))
            .unwrap(),
        );

        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            r"
regions:
  1: null
  900:
    regionid: 900
    regioncode: custom-east
    regionname: My region east
    nodes:
      - name: 900a
        regionid: 900
        hostname: derp900a.example.com
        ipv4: 198.51.100.1
        ipv6: 2001:db8::1
        canport80: true
"
        )
        .unwrap();

        let config = DerpConfig {
            urls: vec!["https://derp.example/map.json".to_string()],
            paths: vec![file.path().to_path_buf()],
            ..DerpConfig::default()
        };

        let map = load_static_derp_map(&config, &fixtures).unwrap();
        assert!(!map.omit_default_regions);
        assert!(map.home_params.is_none());
        assert!(!map.regions.contains_key(&1));
        let region = map.regions.get(&900).unwrap();
        assert_eq!(region.region_name, "My region east");
        assert_eq!(region.nodes[0].host_name, "derp900a.example.com");
        assert_eq!(region.nodes[0].ipv4, "198.51.100.1");
        assert!(region.nodes[0].can_port80);
    }

    #[test]
    fn missing_url_fixture_is_ignored_for_offline_static_loading() {
        let config = DerpConfig::default();
        let map = load_static_derp_map(&config, &UrlFixtureMap::new()).unwrap();

        assert!(map.regions.is_empty());
        assert!(!map.omit_default_regions);
    }

    #[test]
    fn url_map_merge_only_regions_and_drops_null_regions() {
        let mut fixtures = UrlFixtureMap::new();
        fixtures.insert(
            "https://derp.example/base.json".to_string(),
            serde_json::to_vec(&serde_json::json!({
                "Regions": {
                    "1": {
                        "RegionID": 1,
                        "RegionCode": "default",
                        "RegionName": "Default",
                        "Nodes": [{
                            "Name": "1a",
                            "RegionID": 1,
                            "HostName": "derp1.example.com"
                        }]
                    }
                }
            }))
            .unwrap(),
        );
        fixtures.insert(
            "https://derp.example/override.json".to_string(),
            serde_json::to_vec(&serde_json::json!({
                "omitDefaultRegions": true,
                "HomeParams": {
                    "RegionScore": {
                        "902": 1.5
                    }
                },
                "Regions": {
                    "1": null,
                    "902": {
                        "RegionID": 902,
                        "RegionCode": "url",
                        "RegionName": "URL DERP",
                        "Nodes": [{
                            "Name": "902a",
                            "RegionID": 902,
                            "HostName": "url.example.com"
                        }]
                    }
                }
            }))
            .unwrap(),
        );

        let config = DerpConfig {
            urls: vec![
                "https://derp.example/base.json".to_string(),
                "https://derp.example/override.json".to_string(),
            ],
            ..DerpConfig::default()
        };

        let map = load_static_derp_map(&config, &fixtures).unwrap();

        assert!(!map.regions.contains_key(&1));
        assert_eq!(map.regions.get(&902).unwrap().region_code, "url");
        assert!(!map.omit_default_regions);
        assert!(map.home_params.is_none());
    }

    #[test]
    fn shuffle_derp_map_matches_headscale_go_for_seeded_single_region() {
        let mut map = derp_map_with_regions(vec![(
            1,
            "nyc",
            "New York City",
            vec!["1f", "1g", "1h", "1i"],
        )]);

        shuffle_derp_map_with_seed(&mut map, "test1.example.com");

        assert_eq!(
            node_names(&map, 1),
            vec![
                "1g".to_string(),
                "1f".to_string(),
                "1i".to_string(),
                "1h".to_string()
            ]
        );
    }

    #[test]
    fn shuffle_derp_map_matches_headscale_go_sorted_region_order() {
        let mut map = derp_map_with_regions(vec![
            (10, "sea", "Seattle", vec!["10b", "10c", "10d"]),
            (2, "sfo", "San Francisco", vec!["2d", "2e", "2f"]),
        ]);

        shuffle_derp_map_with_seed(&mut map, "test2.example.com");

        assert_eq!(
            node_names(&map, 2),
            vec!["2d".to_string(), "2e".to_string(), "2f".to_string()]
        );
        assert_eq!(
            node_names(&map, 10),
            vec!["10d".to_string(), "10c".to_string(), "10b".to_string()]
        );
    }

    #[test]
    fn shuffle_derp_map_matches_headscale_go_additional_seeded_domains() {
        let cases = [
            (
                "test3.example.com",
                [
                    "4f".to_string(),
                    "4h".to_string(),
                    "4g".to_string(),
                    "4i".to_string(),
                ],
            ),
            (
                "different.example.com",
                [
                    "4g".to_string(),
                    "4i".to_string(),
                    "4f".to_string(),
                    "4h".to_string(),
                ],
            ),
            (
                "another.example.com",
                [
                    "4h".to_string(),
                    "4f".to_string(),
                    "4g".to_string(),
                    "4i".to_string(),
                ],
            ),
            (
                "yetanother.example.com",
                [
                    "4i".to_string(),
                    "4h".to_string(),
                    "4f".to_string(),
                    "4g".to_string(),
                ],
            ),
        ];

        for (base_domain, expected) in cases {
            let mut map =
                derp_map_with_regions(vec![(4, "fra", "Frankfurt", vec!["4f", "4g", "4h", "4i"])]);

            shuffle_derp_map_with_seed(&mut map, base_domain);

            assert_eq!(node_names(&map, 4), expected);
        }
    }

    #[test]
    fn shuffle_derp_map_preserves_headscale_go_edge_cases() {
        let mut empty_map = DerpMap::default();
        shuffle_derp_map_with_seed(&mut empty_map, "edge.example.com");
        assert!(empty_map.regions.is_empty());

        let mut empty_region =
            derp_map_with_regions(vec![(1, "empty", "Empty Region", Vec::new())]);
        shuffle_derp_map_with_seed(&mut empty_region, "edge.example.com");
        assert!(node_names(&empty_region, 1).is_empty());

        let mut single_node =
            derp_map_with_regions(vec![(1, "single", "Single Node Region", vec!["1a"])]);
        shuffle_derp_map_with_seed(&mut single_node, "edge.example.com");
        assert_eq!(node_names(&single_node, 1), vec!["1a".to_string()]);
    }

    #[test]
    fn shuffle_derp_map_without_base_domain_preserves_node_set() {
        let mut map = derp_map_with_regions(vec![(
            1,
            "test",
            "Test Region",
            vec!["1a", "1b", "1c", "1d"],
        )]);

        shuffle_derp_map_with_seed(&mut map, "");

        let mut shuffled = node_names(&map, 1);
        shuffled.sort();
        assert_eq!(
            shuffled,
            vec![
                "1a".to_string(),
                "1b".to_string(),
                "1c".to_string(),
                "1d".to_string()
            ]
        );
    }

    #[test]
    fn derp_url_fetch_timeout_matches_headscale_go() {
        assert_eq!(DERP_MAP_FETCH_TIMEOUT, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn fetches_json_url_map_at_startup() {
        let server = httpmock::MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/derp.json");
            then.status(200).json_body(serde_json::json!({
                "Regions": {
                    "902": {
                        "RegionID": 902,
                        "RegionCode": "url",
                        "RegionName": "URL DERP",
                        "Nodes": [{
                            "Name": "902a",
                            "RegionID": 902,
                            "HostName": "url.example.com"
                        }]
                    }
                }
            }));
        });
        let config = DerpConfig {
            urls: vec![server.url("/derp.json")],
            ..DerpConfig::default()
        };

        let map = load_derp_map(&config, "tail.example.org").await.unwrap();

        mock.assert();
        assert_eq!(
            map.regions
                .get(&902)
                .unwrap()
                .nodes
                .first()
                .unwrap()
                .host_name,
            "url.example.com"
        );
    }

    #[test]
    fn rejects_region_id_mismatch_in_path_map() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            r"
regions:
  900:
    regionid: 901
    regioncode: bad
    regionname: Bad
"
        )
        .unwrap();
        let config = DerpConfig {
            urls: Vec::new(),
            paths: vec![file.path().to_path_buf()],
            ..DerpConfig::default()
        };

        let err = load_static_derp_map(&config, &UrlFixtureMap::new()).unwrap_err();
        assert!(format!("{err:#}").contains("does not match"));
    }

    #[test]
    fn embedded_derp_server_requires_stun_listen_addr() {
        let mut config = DerpConfig::default();
        config.server.enabled = true;
        config.server.stun_listen_addr = None;

        let err = validate_static_derp_config(&config).unwrap_err();

        assert!(format!("{err:#}").contains("derp.server.stun_listen_addr is required"));
    }

    fn derp_map_with_regions(
        regions: Vec<(u16, &'static str, &'static str, Vec<&'static str>)>,
    ) -> DerpMap {
        DerpMap {
            regions: regions
                .into_iter()
                .map(|(region_id, region_code, region_name, node_names)| {
                    (
                        region_id,
                        DerpRegion {
                            region_id,
                            region_code: region_code.to_string(),
                            region_name: region_name.to_string(),
                            latitude: 0.0,
                            longitude: 0.0,
                            avoid: false,
                            no_measure_no_home: false,
                            nodes: node_names
                                .into_iter()
                                .map(|name| DerpRegionNode {
                                    name: name.to_string(),
                                    region_id,
                                    host_name: format!("derp{name}.tailscale.com"),
                                    cert_name: String::new(),
                                    ipv4: String::new(),
                                    ipv6: String::new(),
                                    derp_port: 0,
                                    stun_port: 0,
                                    stun_only: false,
                                    insecure_for_tests: false,
                                    stun_test_ip: String::new(),
                                    can_port80: false,
                                })
                                .collect(),
                        },
                    )
                })
                .collect(),
            ..DerpMap::default()
        }
    }

    fn node_names(map: &DerpMap, region_id: u16) -> Vec<String> {
        map.regions
            .get(&region_id)
            .unwrap()
            .nodes
            .iter()
            .map(|node| node.name.clone())
            .collect()
    }
}
