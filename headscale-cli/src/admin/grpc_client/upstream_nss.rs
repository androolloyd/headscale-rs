//! Lookup order for Go's explicitly selected native resolver (PreferGo).

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LookupOrder {
    FilesDns,
    DnsFiles,
    Files,
    Dns,
}

pub(super) fn lookup_order(openbsd_lookup: &[String], resolv_missing: bool) -> LookupOrder {
    if cfg!(any(
        target_os = "android",
        target_os = "ios",
        target_os = "windows"
    )) {
        return LookupOrder::FilesDns;
    }
    if cfg!(target_os = "openbsd") {
        if resolv_missing {
            return LookupOrder::Files;
        }
        return match openbsd_lookup
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            [] | ["bind", "file"] => LookupOrder::DnsFiles,
            ["bind"] => LookupOrder::Dns,
            ["file"] => LookupOrder::Files,
            _ => LookupOrder::FilesDns,
        };
    }
    let Ok(source) = std::fs::read_to_string("/etc/nsswitch.conf") else {
        return LookupOrder::FilesDns;
    };
    let Some(sources) = parse_sources(&source) else {
        return LookupOrder::FilesDns;
    };
    let has_dns = sources.iter().any(|source| source == "dns");
    let mut first = None;
    let mut files = false;
    let mut dns = false;
    for source in sources {
        match source.as_str() {
            "files" => {
                files = true;
                first.get_or_insert("files");
            }
            "dns" => {
                dns = true;
                first.get_or_insert("dns");
            }
            // With PreferGo, unknown sources count as DNS only when there
            // is no explicit DNS source elsewhere. Criteria are parsed but
            // not executed, matching Go when cgo is unavailable/disabled.
            _ if !has_dns => {
                dns = true;
                first.get_or_insert("dns");
            }
            _ => {}
        }
    }
    match (files, dns, first) {
        (true, true, Some("dns")) => LookupOrder::DnsFiles,
        (true, false, _) => LookupOrder::Files,
        (false, true, _) => LookupOrder::Dns,
        _ => LookupOrder::FilesDns,
    }
}

fn parse_sources(source: &str) -> Option<Vec<String>> {
    let mut hosts = Vec::new();
    for line in source.lines() {
        let line = trim(line.split('#').next().unwrap_or_default());
        if line.is_empty() {
            continue;
        }
        let (database, mut sources) = line.split_once(':')?;
        let database = trim(database);
        loop {
            sources = trim(sources);
            if sources.is_empty() {
                break;
            }
            // Go's NSS parser separates sources at ASCII space, then trims
            // surrounding whitespace. Preserve that behavior for odd inputs.
            let (name, rest) = sources.split_once(' ').unwrap_or((sources, ""));
            sources = trim(rest);
            if let Some(criteria) = sources.strip_prefix('[') {
                let (criteria, rest) = criteria.split_once(']')?;
                for criterion in criteria.split_ascii_whitespace() {
                    let criterion = criterion.strip_prefix('!').unwrap_or(criterion);
                    if criterion.len() < 3 || !criterion.contains('=') {
                        return None;
                    }
                }
                sources = rest;
            }
            if database == "hosts" {
                hosts.push(name.to_string());
            }
        }
    }
    Some(hosts)
}

fn trim(value: &str) -> &str {
    value.trim_matches(|ch: char| ch.is_ascii_whitespace())
}
