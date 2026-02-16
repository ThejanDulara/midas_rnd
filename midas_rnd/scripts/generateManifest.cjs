// scripts/generateManifest.js
const fs = require("fs");
const path = require("path");

const MEDIA_DIR = path.join(process.cwd(), "public", "ai-highlights");
const OUT_FILE = path.join(MEDIA_DIR, "manifest.json");

// Allowed file types
const IMAGE_EXTS = new Set([".jpg", ".jpeg", ".png", ".webp", ".gif"]);
const VIDEO_EXTS = new Set([".mp4", ".webm", ".ogg", ".ogv"]);
const POSTER_EXTS = new Set([".jpg", ".jpeg", ".png", ".webp"]);

// Natural-ish sort (so 2 < 10)
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

if (!fs.existsSync(MEDIA_DIR)) {
  fs.mkdirSync(MEDIA_DIR, { recursive: true });
}

const files = fs.readdirSync(MEDIA_DIR).filter(f => !f.startsWith("."));

// Group by basename to match videos with posters
const byBase = new Map();
for (const file of files) {
  const ext = path.extname(file).toLowerCase();
  const base = path.basename(file, ext);
  const entry = byBase.get(base) || { images: [], videos: [], posters: [] };

  if (IMAGE_EXTS.has(ext)) entry.images.push(file);
  else if (VIDEO_EXTS.has(ext)) entry.videos.push(file);
  if (POSTER_EXTS.has(ext)) entry.posters.push(file); // may overlap with images

  byBase.set(base, entry);
}

const media = [];

// Build media list
for (const [base, group] of byBase.entries()) {
  // Add videos first (with optional poster)
  for (const v of group.videos) {
    // Find poster with same basename (if exists)
    const poster = group.posters.find(p => path.basename(p, path.extname(p)) === base);
    media.push({
      type: "video",
      src: `/ai-highlights/${v}`,
      poster: poster ? `/ai-highlights/${poster}` : undefined,
      alt: base.replace(/[-_]+/g, " "),
    });
  }

  // Add standalone images that aren’t exclusively posters for a video
  // If this basename also has a video and a poster, skip the poster image
  const hasVideo = group.videos.length > 0;
  for (const img of group.images) {
    const isPosterForVideo = hasVideo && group.posters.includes(img);
    if (!isPosterForVideo) {
      media.push({
        type: "image",
        src: `/ai-highlights/${img}`,
        alt: path.basename(img, path.extname(img)).replace(/[-_]+/g, " "),
      });
    }
  }
}

// Sort for stable order (by src)
media.sort((a, b) => collator.compare(a.src, b.src));

// Write manifest
fs.writeFileSync(OUT_FILE, JSON.stringify(media, null, 2));
console.log(`✅ Wrote ${media.length} items to /public/ai-highlights/manifest.json`);
