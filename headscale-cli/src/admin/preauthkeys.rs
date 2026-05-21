//! `headscale preauthkeys {create,list,expire}` — wraps
//! `/api/v1/preauthkeys`.

use headscale_api::admin::{PreauthAdminKey, PreauthMintRequest};

use super::AdminError;
use super::client::AdminClient;
use super::output::{OutputFormat, print_json, print_table};

#[allow(clippy::too_many_arguments)]
pub async fn create(
    client: &AdminClient,
    user: &str,
    reusable: bool,
    ephemeral: bool,
    tags: Vec<String>,
    expires_in_secs: u64,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let body = PreauthMintRequest {
        user: user.to_string(),
        ttl_secs: expires_in_secs,
        reusable,
        ephemeral,
        tags,
    };
    let key: PreauthAdminKey = client.post_json("/preauthkeys", &body).await?;
    match fmt {
        OutputFormat::Json => print_json(&key)?,
        OutputFormat::Table => {
            // Mint flow is the one path that intentionally splashes
            // the full secret — the operator hands it to the device
            // and never sees it again.
            println!("Minted preauth key for user '{}':", key.user);
            println!("  {}", key.key);
            println!("  expires_at: {}", key.expires_at);
            println!("  reusable:   {}", key.reusable);
            println!("  ephemeral:  {}", key.ephemeral);
            if !key.tags.is_empty() {
                println!("  tags:       {}", key.tags.join(","));
            }
        }
    }
    Ok(())
}

pub async fn list(
    client: &AdminClient,
    user_filter: Option<&str>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let mut keys: Vec<PreauthAdminKey> = client.get_json("/preauthkeys").await?;
    if let Some(u) = user_filter {
        keys.retain(|k| k.user == u);
    }
    match fmt {
        OutputFormat::Json => print_json(&keys)?,
        OutputFormat::Table => render_keys(&keys),
    }
    Ok(())
}

pub async fn expire(client: &AdminClient, prefix: &str) -> Result<(), AdminError> {
    let path = format!("/preauthkeys/{prefix}/expire");
    client.post_no_content(&path).await?;
    println!("Expired preauth key '{prefix}'");
    Ok(())
}

fn render_keys(keys: &[PreauthAdminKey]) {
    if keys.is_empty() {
        println!("No preauth keys.");
        return;
    }
    let rows: Vec<Vec<String>> = keys
        .iter()
        .map(|k| {
            vec![
                short_prefix(&k.key),
                k.user.clone(),
                k.reusable.to_string(),
                k.ephemeral.to_string(),
                k.expires_at.to_string(),
                if k.tags.is_empty() {
                    "-".into()
                } else {
                    k.tags.join(",")
                },
            ]
        })
        .collect();
    print_table(
        &[
            "PREFIX",
            "USER",
            "REUSABLE",
            "EPHEMERAL",
            "EXPIRES_AT",
            "TAGS",
        ],
        &rows,
    );
}

/// Show the upstream display prefix for modern pre-auth keys.
fn short_prefix(key: &str) -> String {
    const TOKEN_PREFIX: &str = "hskey-auth-";
    const TOKEN_PREFIX_LEN: usize = 12;
    if let Some(rest) = key.strip_prefix(TOKEN_PREFIX)
        && rest.len() >= TOKEN_PREFIX_LEN
    {
        return format!("{TOKEN_PREFIX}{}-***", &rest[..TOKEN_PREFIX_LEN]);
    }
    key.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_prefix_truncates_long_keys() {
        let s = format!("hskey-auth-{}-{}", "a".repeat(12), "b".repeat(64));
        let out = short_prefix(&s);
        assert_eq!(out, "hskey-auth-aaaaaaaaaaaa-***");
    }

    #[test]
    fn short_prefix_passes_through_short_keys() {
        assert_eq!(short_prefix("short"), "short");
    }
}
