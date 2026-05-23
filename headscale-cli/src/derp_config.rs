//! DERP source loading for upstream-shaped `derp:` config.
//!
//! Startup loading can fetch JSON URL maps and merge local YAML path maps into
//! the wire `DerpMap`. Config validation uses the same local path-map parser
//! without fetching URLs; periodic auto-update remains runtime work.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use headscale_api::tailscale_wire::wire::DerpHomeParams;
use headscale_api::tailscale_wire::{DerpMap, DerpRegion, DerpRegionNode};
use serde::{Deserialize, Serialize};

const DEFAULT_DERP_URL: &str = "https://controlplane.tailscale.com/derpmap/default";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct DerpConfig {
    /// Embedded DERP server settings from upstream headscale v0.28.
    pub server: UpstreamDerpServerConfig,
    /// Externally available DERP maps encoded as JSON.
    pub urls: Vec<String>,
    /// Local DERP map files encoded as YAML.
    pub paths: Vec<PathBuf>,
    /// Parsed for config parity only; no live update worker is wired here.
    pub auto_update_enabled: bool,
    /// Parsed for config parity only; no live update worker is wired here.
    #[serde(deserialize_with = "crate::config::deserialize_duration_secs_from_int_or_string")]
    pub update_frequency: u64,
}

impl Default for DerpConfig {
    fn default() -> Self {
        Self {
            server: UpstreamDerpServerConfig::default(),
            urls: vec![DEFAULT_DERP_URL.to_string()],
            paths: Vec::new(),
            auto_update_enabled: true,
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
        let source: DerpMap = serde_json::from_slice(bytes)
            .with_context(|| format!("parse DERP JSON fixture for {url}"))?;
        merge_derp_map(&mut map, source);
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

pub(crate) async fn load_derp_map(config: &DerpConfig) -> Result<DerpMap> {
    validate_derp_flags(config)?;

    let mut map = DerpMap::default();

    for url in &config.urls {
        let response = reqwest::get(url)
            .await
            .with_context(|| format!("fetch DERP JSON map {url}"))?
            .error_for_status()
            .with_context(|| format!("fetch DERP JSON map {url}"))?;
        let bytes = response
            .bytes()
            .await
            .with_context(|| format!("read DERP JSON map {url}"))?;
        let source: DerpMap =
            serde_json::from_slice(&bytes).with_context(|| format!("parse DERP JSON map {url}"))?;
        merge_derp_map(&mut map, source);
    }

    for path in &config.paths {
        let source = load_derp_path_map(path)?;
        apply_path_map(&mut map, source)
            .with_context(|| format!("apply DERP YAML path map {}", path.display()))?;
    }

    Ok(map)
}

fn load_derp_path_map(path: &Path) -> Result<DerpPathMap> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read DERP YAML path map {}", path.display()))?;
    serde_yaml::from_str(&contents)
        .with_context(|| format!("parse DERP YAML path map {}", path.display()))
}

fn merge_derp_map(dest: &mut DerpMap, source: DerpMap) {
    if source.home_params.is_some() {
        dest.home_params = source.home_params;
    }
    dest.regions.extend(source.regions);
    if source.omit_default_regions {
        dest.omit_default_regions = true;
    }
}

fn apply_path_map(dest: &mut DerpMap, source: DerpPathMap) -> Result<()> {
    if let Some(home_params) = source.home_params {
        dest.home_params = Some(home_params.into_wire());
    }
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
    #[serde(default, alias = "homeParams", alias = "HomeParams")]
    home_params: Option<PathDerpHomeParams>,
}

#[derive(Debug, Deserialize)]
struct PathDerpHomeParams {
    #[serde(default, alias = "regionScore", alias = "RegionScore")]
    region_score: HashMap<u16, f64>,
}

impl PathDerpHomeParams {
    fn into_wire(self) -> DerpHomeParams {
        DerpHomeParams {
            region_score: self.region_score,
        }
    }
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
        assert!(map.omit_default_regions);
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

        let map = load_derp_map(&config).await.unwrap();

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
}
