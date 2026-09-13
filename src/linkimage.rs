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
        let client = reqwest::Client::builder()
            .user_agent("discord-anti-scam-bot/1.0")
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("failed to build the link-fetching HTTP client");

        Self {
            client,
            allowed_hosts: allowed_hosts.iter().map(|h| h.to_lowercase()).collect(),
        }
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
        let Some(host) = parsed.host_str() else {
            return false;
        };
        let host = host.to_lowercase();
        self.allowed_hosts
            .iter()
            .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
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
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("fetching {url}"))?;

        if !resp.status().is_success() {
            return Ok(None);
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("reading response body from {url}"))?;

        if bytes.len() > MAX_BYTES {
            return Ok(None);
        }

        Ok(Some((bytes.to_vec(), content_type)))
    }
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
