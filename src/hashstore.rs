use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use image::{DynamicImage, GenericImageView};
use image_hasher::{HashAlg, Hasher, HasherConfig, ImageHash};
use tokio::sync::RwLock;

pub struct MatchResult {
    pub filename: String,
    pub distance: u32,
}

/// A perceptual hash of an image plus a few hashes of cropped variants of it
/// (center + corners, at a couple of crop ratios). Global perceptual hashes are
/// fragile to cropping — a screenshot with a sliver trimmed off an edge to dodge
/// detection would otherwise hash very differently. Comparing every variant of an
/// incoming image against every variant of a reference catches that case.
pub struct ImageVariants {
    /// Hash of the untouched image — what flood-detection (same-post-many-channels)
    /// compares against, since that's about literal reposts, not evasion crops.
    pub primary: ImageHash,
    all: Vec<ImageHash>,
}

impl ImageVariants {
    fn min_dist(&self, other: &ImageVariants) -> u32 {
        self.all
            .iter()
            .flat_map(|a| other.all.iter().map(move |b| a.dist(b)))
            .min()
            .unwrap_or(u32::MAX)
    }
}

/// Stores perceptual hashes of reference images (screenshots of already-identified
/// compromised accounts) and lets you compare a new image against that set.
pub struct ReferenceStore {
    hasher: Hasher,
    entries: RwLock<HashMap<String, ImageVariants>>,
    dir: PathBuf,
}

impl ReferenceStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let hasher = HasherConfig::new()
            .hash_alg(HashAlg::DoubleGradient)
            .hash_size(16, 16)
            .to_hasher();
        Self {
            hasher,
            entries: RwLock::new(HashMap::new()),
            dir: dir.into(),
        }
    }

    /// Returns center + corner crops at a couple of mild ratios (dodges a thin
    /// border trim), plus aggressive *center-only* crops down to a third of the
    /// image, including thin strips. The actual scam content in a screenshot sits
    /// in the middle, not at the edges (UI chrome, timestamps...), so someone
    /// keeping only e.g. the middle vertical third must still match on that region.
    fn crop_variants(img: &DynamicImage) -> Vec<DynamicImage> {
        let (w, h) = img.dimensions();
        let mut variants = vec![img.clone()];

        for &ratio in &[0.85_f32, 0.7_f32] {
            Self::push_crops(img, w, h, ratio, ratio, true, &mut variants);
        }

        for &(wr, hr) in &[
            (0.55_f32, 0.55_f32),
            (0.4_f32, 0.4_f32),
            (0.33_f32, 1.0_f32), // middle vertical strip (kept width only)
            (1.0_f32, 0.33_f32), // middle horizontal strip (kept height only)
            (0.5_f32, 1.0_f32),
            (1.0_f32, 0.5_f32),
        ] {
            Self::push_crops(img, w, h, wr, hr, false, &mut variants);
        }

        variants
    }

    /// Pushes a center crop of size `(w*wr, h*hr)`, and optionally the same size
    /// crop anchored at each of the four corners.
    fn push_crops(
        img: &DynamicImage,
        w: u32,
        h: u32,
        wr: f32,
        hr: f32,
        include_corners: bool,
        out: &mut Vec<DynamicImage>,
    ) {
        let cw = ((w as f32 * wr) as u32).clamp(1, w);
        let ch = ((h as f32 * hr) as u32).clamp(1, h);

        out.push(img.crop_imm((w - cw) / 2, (h - ch) / 2, cw, ch));

        if include_corners {
            let anchors = [(0, 0), (w - cw, 0), (0, h - ch), (w - cw, h - ch)];
            for (x, y) in anchors {
                out.push(img.crop_imm(x, y, cw, ch));
            }
        }
    }

    fn hash_image(&self, img: &DynamicImage) -> ImageVariants {
        let primary = self.hasher.hash_image(img);
        let all = Self::crop_variants(img)
            .iter()
            .map(|v| self.hasher.hash_image(v))
            .collect();
        ImageVariants { primary, all }
    }

    fn hash_file(&self, path: &Path) -> Result<ImageVariants> {
        let mut reader = image::ImageReader::open(path)
            .with_context(|| format!("could not open {}", path.display()))?
            .with_guessed_format()
            .with_context(|| format!("could not guess format of {}", path.display()))?;
        reader.limits(decode_limits());
        let img = reader
            .decode()
            .with_context(|| format!("could not decode {}", path.display()))?;
        Ok(self.hash_image(&img))
    }

    pub fn hash_bytes(&self, bytes: &[u8]) -> Result<ImageVariants> {
        let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format()?;
        reader.limits(decode_limits());
        let img = reader.decode()?;
        Ok(self.hash_image(&img))
    }

    /// (Re)loads every image file in the reference folder into memory.
    pub async fn load_dir(&self) -> Result<usize> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("could not create folder {}", self.dir.display()))?;

        let mut map = HashMap::new();
        for entry in std::fs::read_dir(&self.dir)
            .with_context(|| format!("could not read folder {}", self.dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            match self.hash_file(&path) {
                Ok(hash) => {
                    let name = path.file_name().unwrap().to_string_lossy().to_string();
                    map.insert(name, hash);
                }
                Err(e) => {
                    tracing::warn!("could not hash {}: {e:#}", path.display());
                }
            }
        }
        let count = map.len();
        *self.entries.write().await = map;
        Ok(count)
    }

    /// Finds the closest reference to a given image (minimum Hamming distance across
    /// every crop variant of both sides).
    pub async fn best_match(&self, hash: &ImageVariants) -> Option<MatchResult> {
        let map = self.entries.read().await;
        map.iter()
            .map(|(name, h)| MatchResult {
                filename: name.clone(),
                distance: hash.min_dist(h),
            })
            .min_by_key(|m| m.distance)
    }

    /// Adds a new reference image (persisted to disk + hashed in memory).
    pub async fn add_from_bytes(&self, filename: &str, bytes: &[u8]) -> Result<()> {
        if !is_safe_filename(filename) {
            anyhow::bail!("invalid reference filename: {filename:?}");
        }
        let path = self.dir.join(filename);
        std::fs::write(&path, bytes)
            .with_context(|| format!("could not write {}", path.display()))?;
        let hash = match self.hash_file(&path) {
            Ok(h) => h,
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                return Err(e);
            }
        };
        self.entries.write().await.insert(filename.to_string(), hash);
        Ok(())
    }

    pub async fn remove(&self, filename: &str) -> Result<bool> {
        if !is_safe_filename(filename) {
            return Ok(false);
        }
        let existed = self.entries.write().await.remove(filename).is_some();
        let path = self.dir.join(filename);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(existed)
    }

    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    pub async fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = self.entries.read().await.keys().cloned().collect();
        v.sort();
        v
    }
}

/// Caps how much memory a single image decode may use. `image`'s own default
/// (512 MiB, no dimension limit) is a safety net against decompression bombs
/// but still generous enough that a handful of concurrent malicious decodes
/// could exhaust memory on a small host. Every image we hash gets downsampled
/// to a 16x16 grid anyway, so there's no legitimate need for headroom anywhere
/// near the default — 128 MiB comfortably covers even a large real screenshot
/// (a 4K RGBA frame is ~32 MiB decoded) with plenty of margin.
fn decode_limits() -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(128 * 1024 * 1024);
    limits
}

/// A reference filename must be a single plain path component — no directory
/// separators, no `..`. `add_from_bytes` and `remove` both take a filename that
/// (transitively) comes from user input (a Discord attachment name, or a
/// `!scam remove <name>` argument), and both do `self.dir.join(filename)` —
/// without this check, `!scam remove ../../.env` would happily delete a file
/// outside `reference/` entirely. This is a hard boundary, not just cleanliness.
fn is_safe_filename(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A cropped repost of a known reference (someone trimming an edge to dodge
    /// detection) must still match — this is the whole point of `crop_variants`.
    #[tokio::test]
    async fn matches_a_cropped_repost() {
        let store = ReferenceStore::new("reference");
        let loaded = store.load_dir().await.expect("load reference dir");
        assert!(loaded > 0, "expected at least one reference image in ./reference");

        // image.jpg and image8.jpg are near-duplicates of each other in this reference
        // set, so we use image3.jpg here to unambiguously check which file matched.
        let img = image::open("reference/image3.jpg").expect("open reference/image3.jpg");
        let (w, h) = img.dimensions();
        // Asymmetric crop that doesn't line up with any single precomputed anchor,
        // to make sure the tolerance isn't just an artifact of picking matching ratios.
        let cropped = img.crop_imm(w / 20, h / 8, w * 9 / 10, h * 4 / 5);

        let mut bytes = Vec::new();
        cropped
            .write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .expect("encode cropped image");

        let hash = store.hash_bytes(&bytes).expect("hash cropped image");
        let m = store.best_match(&hash).await.expect("a best match");

        assert_eq!(m.filename, "image3.jpg");
        assert!(
            m.distance <= 20,
            "cropped repost should still match closely, got distance {}",
            m.distance
        );
    }

    /// Same idea but with only the middle vertical third of the image kept —
    /// the exact case reported as a miss before `crop_variants` covered strips.
    #[tokio::test]
    async fn matches_middle_vertical_third_only() {
        let store = ReferenceStore::new("reference");
        store.load_dir().await.expect("load reference dir");

        let img = image::open("reference/image3.jpg").expect("open reference/image3.jpg");
        let (w, h) = img.dimensions();
        let third = w / 3;
        let cropped = img.crop_imm(third, 0, third, h);

        let mut bytes = Vec::new();
        cropped
            .write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .expect("encode cropped image");

        let hash = store.hash_bytes(&bytes).expect("hash cropped image");
        let m = store.best_match(&hash).await.expect("a best match");

        assert_eq!(m.filename, "image3.jpg");
        assert!(
            m.distance <= 20,
            "middle-third-only repost should still match closely, got distance {}",
            m.distance
        );
    }

    /// Security regression: `!scam remove`/`!scam add` filenames come from user
    /// input (Discord attachment names / command arguments). Neither must be able
    /// to escape the reference directory.
    #[tokio::test]
    async fn rejects_path_traversal_in_filenames() {
        let dir = std::env::temp_dir().join(format!(
            "discord_anti_scam_bot_traversal_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let outside_target = std::env::temp_dir().join(format!(
            "discord_anti_scam_bot_traversal_victim_{}.txt",
            std::process::id()
        ));
        std::fs::write(&outside_target, b"do not delete me").expect("create victim file");

        let store = ReferenceStore::new(&dir);
        store.load_dir().await.expect("create reference dir");

        for evil in [
            "../victim.txt",
            "../../etc/passwd",
            "a/b.jpg",
            "..",
            "",
            "/etc/passwd",
        ] {
            let added = store.add_from_bytes(evil, b"fake image").await;
            assert!(added.is_err(), "add_from_bytes should reject {evil:?}");

            let removed = store.remove(evil).await.expect("remove should not error");
            assert!(!removed, "remove should reject {evil:?} rather than touch it");
        }

        assert!(outside_target.exists(), "file outside reference/ must survive");
        assert_eq!(
            std::fs::read_to_string(&outside_target).unwrap(),
            "do not delete me"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&outside_target);
    }
}
