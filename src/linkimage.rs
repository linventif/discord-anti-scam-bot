use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Duration;

use anyhow::{Context, Result};
use regex::Regex;

/// Refuse to buffer more than this many bytes for a linked image (same order of
/// magnitude as Discord's own attachment limits).
const MAX_BYTES: usize = 15 * 1024 * 1024;
/// Don't bother scanning more than a handful of links per message.
const MAX_URLS_PER_MESSAGE: usize = 4;

static URL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"https?://[^\s<>]+").unwrap());
static META_TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<meta\b[^>]*>").unwrap());
static OG_IMAGE_PROPERTY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)property\s*=\s*["']og:image[^"']*["']"#).unwrap());
static CONTENT_ATTR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)content\s*=\s*["']([^"']+)["']"#).unwrap());

/// Fetches images posted as plain links rather than attachments (e.g. an imgur
/// link). Only hosts on an explicit allow-list are ever fetched — the bot must
/// not become an open URL-fetching proxy for whatever a message happens to
/// contain, since that's an SSRF vector against internal services.
pub struct LinkImageFetcher {
    client: reqwest::Client,
    allowed_hosts: Vec<String>,
}

impl LinkImageFetcher {
    pub fn new(allowed_hosts: &[String]) -> Self {
        let allowed_hosts: Vec<String> = allowed_hosts.iter().map(|h| h.to_lowercase()).collect();

        // The initial URL's host is checked in `extract_urls`, but an allow-listed
        // host issuing a redirect isn't itself vetted by that — without this, a
        // compromised/malicious allow-listed host (or an open redirect on one)
        // could steer the fetch at an internal address. Re-check every hop.
        let redirect_hosts = allowed_hosts.clone();
        let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
            if host_is_allowed(attempt.url(), &redirect_hosts) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        });

        let client = reqwest::Client::builder()
            .user_agent("discord-anti-scam-bot/1.0")
            .timeout(Duration::from_secs(8))
            .redirect(redirect_policy)
            .build()
            .expect("failed to build the link-fetching HTTP client");

        Self { client, allowed_hosts }
    }

    /// Extracts candidate image URLs from message text whose host is allow-listed.
    pub fn extract_urls(&self, content: &str) -> Vec<String> {
        URL_RE
            .find_iter(content)
            .map(|m| {
                m.as_str()
                    .trim_end_matches(['>', ')', ',', '.', '!', '?'])
                    .to_string()
            })
            .filter(|u| self.host_allowed(u))
            .collect::<HashSet<_>>()
            .into_iter()
            .take(MAX_URLS_PER_MESSAGE)
            .collect()
    }

    fn host_allowed(&self, url: &str) -> bool {
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return false;
        };
        host_is_allowed(&parsed, &self.allowed_hosts)
    }

    /// Downloads the bytes of an image URL. If the URL points at an HTML page
    /// (e.g. an imgur gallery page rather than a direct image link), follows its
    /// `og:image` meta tag once to find the actual image.
    pub async fn fetch_image_bytes(&self, url: &str) -> Result<Option<Vec<u8>>> {
        let Some((bytes, content_type)) = self.get_with_content_type(url).await? else {
            return Ok(None);
        };

        if content_type.starts_with("image/") {
            return Ok(Some(bytes));
        }

        if content_type.starts_with("text/html") {
            let html = String::from_utf8_lossy(&bytes);
            if let Some(og_url) = find_og_image(&html) {
                if let Some((bytes2, ct2)) = self.get_with_content_type(&og_url).await? {
                    if ct2.starts_with("image/") {
                        return Ok(Some(bytes2));
                    }
                }
            }
        }

        Ok(None)
    }

    async fn get_with_content_type(&self, url: &str) -> Result<Option<(Vec<u8>, String)>> {
        let mut resp = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("fetching {url}"))?;

        if !resp.status().is_success() {
            return Ok(None);
        }

        // Bail before downloading anything if the server is upfront about a
        // too-large body, and enforce the same cap while streaming in case it
        // isn't (or lies) — an allow-listed host is still not a host we trust
        // to hand us an unbounded response and have us buffer all of it.
        if resp.content_length().is_some_and(|len| len > MAX_BYTES as u64) {
            return Ok(None);
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let mut bytes = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .with_context(|| format!("reading response body from {url}"))?
        {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > MAX_BYTES {
                return Ok(None);
            }
        }

        Ok(Some((bytes, content_type)))
    }
}

fn host_is_allowed(url: &reqwest::Url, allowed_hosts: &[String]) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.to_lowercase();
    allowed_hosts
        .iter()
        .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
}

fn find_og_image(html: &str) -> Option<String> {
    for tag in META_TAG_RE.find_iter(html) {
        let tag_str = tag.as_str();
        if OG_IMAGE_PROPERTY_RE.is_match(tag_str) {
            if let Some(cap) = CONTENT_ATTR_RE.captures(tag_str) {
                return Some(cap[1].to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetcher() -> LinkImageFetcher {
        LinkImageFetcher::new(&[
            "imgur.com".to_string(),
            "i.imgur.com".to_string(),
        ])
    }

    /// The same check gates both the initial URL and every redirect hop
    /// (`Policy::custom` in `new`) — this locks in the logic a compromised or
    /// open-redirecting allow-listed host would need to bypass to steer a fetch
    /// at an internal address.
    #[test]
    fn host_is_allowed_rejects_redirect_targets_outside_the_allow_list() {
        let allowed = vec!["imgur.com".to_string()];
        let allowed_url = reqwest::Url::parse("https://imgur.com/x.png").unwrap();
        let internal_url = reqwest::Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        let lookalike_url = reqwest::Url::parse("https://imgur.com.evil.tld/x.png").unwrap();

        assert!(host_is_allowed(&allowed_url, &allowed));
        assert!(!host_is_allowed(&internal_url, &allowed));
        assert!(!host_is_allowed(&lookalike_url, &allowed));
    }

    #[test]
    fn extracts_only_allow_listed_hosts() {
        let f = fetcher();
        let urls = f.extract_urls(
            "check this out https://i.imgur.com/abc123.png and also https://evil.example.com/x.png",
        );
        assert_eq!(urls, vec!["https://i.imgur.com/abc123.png".to_string()]);
    }

    #[test]
    fn still_extracts_a_suppressed_embed_link() {
        // Discord's <...> syntax suppresses the visual embed, but the bot must
        // still notice the URL itself instead of relying on Discord's embed.
        let f = fetcher();
        let urls = f.extract_urls("sneaky repost <https://imgur.com/gallery/abc123>");
        assert_eq!(urls, vec!["https://imgur.com/gallery/abc123".to_string()]);
    }

    #[test]
    fn rejects_lookalike_hosts() {
        let f = fetcher();
        // "notimgur.com" and "imgur.com.evil.tld" must not pass as imgur.com.
        let urls = f.extract_urls(
            "https://notimgur.com/x.png https://imgur.com.evil.tld/x.png",
        );
        assert!(urls.is_empty());
    }

    #[test]
    fn finds_og_image_regardless_of_attribute_order() {
        let html = r#"<html><head>
            <meta content="https://i.imgur.com/real.png" property="og:image">
        </head></html>"#;
        assert_eq!(
            find_og_image(html),
            Some("https://i.imgur.com/real.png".to_string())
        );
    }
}
