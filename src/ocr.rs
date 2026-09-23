use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use image::{DynamicImage, GenericImageView};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Semaphore;

use crate::config::{OcrConfig, OcrRule};

/// Reads the text in an image (via the `tesseract` CLI) and scores it against a
/// list of weighted scam phrases. Catches *new* variants of a known scam template
/// — same fake MrBeast tweet / "Withdrawal Success" popup, different domain,
/// promo code, amounts and cropping — that perceptual hashing can't, since the
/// pixels are different but the wording barely changes between waves.
///
/// Shells out to the `tesseract` binary instead of linking libtesseract: no C++
/// build dependency, and a missing binary just disables OCR instead of breaking
/// the build. The image is decoded by us (with the same memory limits as
/// `hashstore.rs`), downscaled and re-encoded as a plain RGB PNG before
/// being piped in, so tesseract/leptonica never parse untrusted image bytes.
pub struct OcrScanner {
    tesseract_path: String,
    languages: String,
    timeout: Duration,
    max_dimension: u32,
    score_threshold: u32,
    rules: Vec<NormalizedRule>,
    permits: Semaphore,
}

struct NormalizedRule {
    /// As written in the config, for the detection log.
    label: String,
    normalized: String,
    weight: u32,
}

#[derive(Debug, PartialEq)]
pub struct OcrMatch {
    pub score: u32,
    pub matched: Vec<String>,
}

/// Images smaller than this (emoji, stickers, avatars...) are not worth an OCR pass.
const MIN_DIMENSION: u32 = 64;

impl OcrScanner {
    /// Returns `None` (OCR disabled) if it's turned off in the config, or if the
    /// configured tesseract binary can't be run — logged, but not fatal, so a
    /// bare `cargo run` without tesseract installed still works.
    pub async fn new(cfg: &OcrConfig) -> Option<Self> {
        if !cfg.enabled {
            tracing::info!("OCR detection disabled in config");
            return None;
        }

        match Command::new(&cfg.tesseract_path)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
        {
            Ok(status) if status.success() => {}
            Ok(status) => {
                tracing::warn!("OCR disabled: `{} --version` exited with {status}", cfg.tesseract_path);
                return None;
            }
            Err(e) => {
                tracing::warn!("OCR disabled: could not run `{}`: {e}", cfg.tesseract_path);
                return None;
            }
        }

        let rules = if cfg.rules.is_empty() { default_rules() } else { cfg.rules.clone() };
        let scanner = Self::with_rules(cfg, &rules);
        tracing::info!(
            "OCR detection enabled ({}, {} rule(s), threshold {})",
            cfg.languages,
            scanner.rules.len(),
            cfg.score_threshold
        );
        Some(scanner)
    }

    fn with_rules(cfg: &OcrConfig, rules: &[OcrRule]) -> Self {
        let rules = rules
            .iter()
            .map(|r| NormalizedRule {
                label: r.pattern.clone(),
                normalized: normalize(&r.pattern),
                weight: r.weight,
            })
            .filter(|r| !r.normalized.is_empty())
            .collect();
        Self {
            tesseract_path: cfg.tesseract_path.clone(),
            languages: cfg.languages.clone(),
            timeout: Duration::from_secs(cfg.timeout_seconds.max(1)),
            max_dimension: cfg.max_dimension.max(MIN_DIMENSION),
            score_threshold: cfg.score_threshold,
            rules,
            permits: Semaphore::new(cfg.max_concurrent.max(1)),
        }
    }

    /// Runs OCR on the image and returns the match if its text scores at or above
    /// the threshold.
    pub async fn check(&self, bytes: &[u8]) -> Result<Option<OcrMatch>> {
        let Some(text) = self.extract_text(bytes).await? else {
            return Ok(None);
        };
        let m = self.score(&text);
        tracing::debug!("OCR score {} (matched: {:?})", m.score, m.matched);
        Ok((m.score >= self.score_threshold).then_some(m))
    }

    /// Scores a piece of (OCR'd) text against every rule. Each rule counts once,
    /// however many times its phrase appears.
    pub fn score(&self, text: &str) -> OcrMatch {
        let haystack = format!(" {} ", normalize(text));
        let mut score = 0;
        let mut matched = Vec::new();
        for rule in &self.rules {
            if haystack.contains(&rule.normalized) {
                score += rule.weight;
                matched.push(rule.label.clone());
            }
        }
        OcrMatch { score, matched }
    }

    /// `Ok(None)` for an image too small to be worth reading.
    async fn extract_text(&self, bytes: &[u8]) -> Result<Option<String>> {
        let max_dimension = self.max_dimension;
        let owned = bytes.to_vec();
        let Some(png) = tokio::task::spawn_blocking(move || prepare_image(&owned, max_dimension))
            .await
            .context("OCR preprocessing task panicked")??
        else {
            return Ok(None);
        };

        // Bounds how many tesseract processes (CPU-heavy) run at once when a
        // flood of images arrives together.
        let _permit = self.permits.acquire().await.context("OCR semaphore closed")?;

        let mut child = Command::new(&self.tesseract_path)
            .args(["stdin", "stdout", "-l", &self.languages])
            // tesseract's OpenMP threads thrash badly when several runs (or other
            // CPU-heavy work) share a few cores — a 1 s read blew past a 15 s
            // timeout on a CI runner. Parallelism comes from `max_concurrent`.
            .env("OMP_THREAD_LIMIT", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("could not spawn {}", self.tesseract_path))?;

        let mut stdin = child.stdin.take().context("tesseract stdin unavailable")?;
        let run = async move {
            stdin.write_all(&png).await.context("could not write image to tesseract")?;
            drop(stdin);
            child.wait_with_output().await.context("tesseract failed")
        };

        let output = match tokio::time::timeout(self.timeout, run).await {
            Ok(r) => r?,
            // Dropping `run` drops the child, which kills it (kill_on_drop).
            Err(_) => bail!("tesseract timed out after {:?}", self.timeout),
        };
        if !output.status.success() {
            bail!("tesseract exited with {}", output.status);
        }
        Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
    }
}

/// Decodes (memory-capped), downscales to `max_dimension`, and re-encodes as an
/// RGB PNG. `Ok(None)` if the image is too small to bother. Deliberately *not*
/// grayscale: on these dark-theme screenshots (green/white text on near-black),
/// a naive luma conversion made tesseract miss the popup text entirely, while
/// its own binarization of the color image reads it fine.
fn prepare_image(bytes: &[u8], max_dimension: u32) -> Result<Option<Vec<u8>>> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format()?;
    reader.limits(crate::hashstore::decode_limits());
    let img = reader.decode().context("could not decode image")?;

    let (w, h) = img.dimensions();
    if w < MIN_DIMENSION || h < MIN_DIMENSION {
        return Ok(None);
    }
    let img = if w > max_dimension || h > max_dimension {
        img.resize(max_dimension, max_dimension, image::imageops::FilterType::Triangle)
    } else {
        img
    };

    let rgb = DynamicImage::ImageRgb8(img.to_rgb8());
    let mut png = Vec::new();
    rgb.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .context("could not encode image for OCR")?;
    Ok(Some(png))
}

/// Lowercases, folds Cyrillic letters that look like Latin ones onto their Latin
/// twin, turns everything that isn't a letter/digit into a space, and collapses
/// whitespace. Running tesseract with `eng+rus` regularly reads Latin text with a
/// few Cyrillic look-alikes mixed in ("Гат pleased", "ВАМК САВО") — folding both
/// the text and the rule patterns the same way makes matching immune to that.
/// Russian patterns still work: they're folded identically on both sides.
fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = true;
    for c in s.chars().flat_map(char::to_lowercase) {
        let c = match c {
            'а' => 'a',
            'в' => 'b',
            'е' | 'ё' => 'e',
            'к' => 'k',
            'м' => 'm',
            'н' => 'h',
            'о' => 'o',
            'р' => 'p',
            'с' => 'c',
            'т' => 't',
            'у' => 'y',
            'х' => 'x',
            'і' => 'i',
            other => other,
        };
        if c.is_alphanumeric() {
            out.push(c);
            last_space = false;
        } else if !last_space {
            out.push(' ');
            last_space = true;
        }
    }
    out.trim_end().to_string()
}

/// Built-in phrases, used when `[[ocr.rules]]` isn't set in config.toml. Weighted
/// so that no single generic word ("bonus", "casino", "withdraw") is enough on
/// its own at the default threshold of 6 — it takes one of the template's very
/// specific phrases, or several weaker signals together.
pub fn default_rules() -> Vec<OcrRule> {
    let r = |pattern: &str, weight: u32| OcrRule { pattern: pattern.to_string(), weight };
    vec![
        // Fake-celebrity crypto casino tweet ("MrBeast launches a casino").
        r("this post will be deleted", 4),
        r("to everyone who registers", 4),
        r("special promo code", 4),
        r("cryptocurrency casino", 4),
        r("claim your reward", 3),
        r("withdraw the bonus", 3),
        r("vyro", 3),
        r("mrbeast", 2),
        r("giving away", 2),
        // Fake casino site ("Activate Code for Bonus", fake withdrawal popup).
        r("was successfully", 4), // the scam's own broken English
        r("activate code for bonus", 4),
        r("withdrawal success", 3),
        r("promo code", 3),
        r("rakeback", 3),
        r("select a withdraw method", 2),
        r("casino", 2),
        r("vip club", 1),
        r("bonus", 1),
        r("withdraw", 1),
        r("wallet", 1),
        // Russian variant ("X opened a casino and gives 10000 rubles to every new user").
        r("каждому новому пользователю", 4),
        r("раздаёт", 3),
        r("казино", 3),
        r("промокод", 3),
        r("после регистрации", 2),
        r("бонус", 1),
        r("рублей", 1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> OcrScanner {
        OcrScanner::with_rules(&OcrConfig::default(), &default_rules())
    }

    // Excerpts of real tesseract (eng+rus) output on the scam screenshots — OCR
    // noise, stray Cyrillic look-alikes and all.
    const TWEET: &str = "MrBeast @ ©] @MrBeast 56т\nГат pleased to announce the launch of my own cryptocurrency casino linked\n\
        to our recent launch of the Vyro project! To celebrate this big event, | am\ngiving away $3,500 to everyone who registers\n\
        How to claim your reward:\nGo to: sedowin.com\nEnter the special promo code: CASH\n\
        This post will be deleted an hour after publication";
    const BONUS_PAGE: &str = "*$ sedowin.com/profile/bonuses\n@ Home $ Profile  Вопизез ¥¢ VIP-Club\nBONUSES\n\
        $ honestly5434.. ‘Activate Code for Bonus\ne Enter the promo code and receive an exclusive rew\nRakeback";
    const WITHDRAW_POPUP: &str = "sedowin.com/profile/withdraw\nWithdrawal Success! x\n\
        Your Withdrawal of $3700.00 Was Successfully!\nThe money will be transferred to your specified wallet.";
    const PHONE_POPUP: &str = "Home § Profile Bonuses VIP-Club\nВег | VISA\nWithdre\n\
        Your balance = ‘Your Withdrawal of $3700.00 Was Successfully!\n— x The money will be transferred to your specified wallet.";
    const RUSSIAN: &str = "< РИА НОВОСТИ\nМеллстрой открыл своё казино ив\nчесть открытия раздаёт 10000\n\
        рублей каждому новому\nпользователю. Бонус можно\nполучить Ha drgn25.casino. После\nрегистрации деньги поступают сразу";

    #[test]
    fn flags_every_screenshot_of_the_new_scam_wave() {
        let s = scanner();
        for (name, text) in [
            ("tweet", TWEET),
            ("bonus page", BONUS_PAGE),
            ("withdraw popup", WITHDRAW_POPUP),
            ("phone popup", PHONE_POPUP),
            ("russian", RUSSIAN),
        ] {
            let m = s.score(text);
            assert!(m.score >= 6, "{name} should be flagged, got {m:?}");
        }
    }

    #[test]
    fn does_not_flag_ordinary_screenshots() {
        let s = scanner();
        for text in [
            // A game/dev screenshot mentioning a bonus.
            "Level 12 complete! Daily bonus: +50 coins. Press E to continue",
            // A legit exchange withdrawal confirmation.
            "Withdrawal successful. Your withdrawal of 0.5 ETH has been sent to your wallet.",
            // Someone talking about a casino map in Garry's Mod.
            "gm_casino loaded - 24 players. Type !help for commands",
            "Error: attempt to index a nil value (field 'Player') lua/autorun/server/init.lua:42",
        ] {
            let m = s.score(text);
            assert!(m.score < 6, "{text:?} should not be flagged, got {m:?}");
        }
    }

    #[test]
    fn normalize_folds_case_punctuation_and_cyrillic_lookalikes() {
        assert_eq!(normalize("Гат pleased!!  VIP-Club"), "гat pleased vip club");
        assert_eq!(normalize("ВАМК САВО"), "bamk cabo");
        assert_eq!(normalize("Раздаёт"), normalize("раздает"));
    }

    /// Only runs where tesseract is installed (the Docker image, CI) — skipped
    /// with a note otherwise, so a bare `cargo test` still passes.
    #[tokio::test]
    async fn reads_a_real_scam_screenshot() {
        // Generous timeout: other tests hash images in parallel on few CI cores.
        let cfg = OcrConfig { timeout_seconds: 120, ..OcrConfig::default() };
        let Some(scanner) = OcrScanner::new(&cfg).await else {
            eprintln!("skipping: tesseract not available");
            return;
        };
        let bytes = std::fs::read("reference/1.jpg").expect("read reference/1.jpg");
        let m = scanner.check(&bytes).await.expect("OCR ran");
        assert!(m.is_some(), "reference/1.jpg (Russian casino scam) should be flagged by OCR");
    }
}
