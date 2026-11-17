import sharp from "sharp";
import { readdir, unlink } from "fs/promises";
import { config } from "./config.ts";

const AVATAR_SIZE = 256;
const WEBP_QUALITY = 82;

// WebP is the only format we write: it is decoded natively by browsers and by
// Flutter's engine (including animated WebP), unlike AVIF. The other extensions
// are kept so pictures stored by earlier versions stay readable until migrated.
const CONTENT_TYPES: Record<string, string> = {
  webp: "image/webp",
  avif: "image/avif",
  jpg: "image/jpeg",
  gif: "image/gif",
};

const CURRENT_EXTENSION = "webp";
const LEGACY_EXTENSIONS = ["avif", "jpg", "gif"];
const ALL_EXTENSIONS = [CURRENT_EXTENSION, ...LEGACY_EXTENSIONS];

// sharp reports the decoder it used as metadata.format ("heif" covers AVIF/HEIC).
const SUPPORTED_INPUT_FORMATS = new Set(["gif", "jpeg", "png", "webp", "heif"]);

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class UnsupportedImageError extends Error {}

function avatarPath(userId: string, extension: string): string {
  return `${config.avatarStorageDir}/${userId}.${extension}`;
}

/** Resize and encode to WebP. `animated: true` keeps every frame of animated input. */
export async function encodeAvatar(data: Uint8Array): Promise<Buffer> {
  return await sharp(data, { animated: true })
    .resize(AVATAR_SIZE, AVATAR_SIZE, { fit: "cover" })
    .webp({ quality: WEBP_QUALITY })
    .toBuffer();
}

export async function saveAvatar(userId: string, data: Uint8Array): Promise<{ extension: string; contentType: string }> {
  const metadata = await sharp(data, { animated: true }).metadata();
  const format = metadata.format ?? "";
  if (!SUPPORTED_INPUT_FORMATS.has(format)) {
    throw new UnsupportedImageError(`Unsupported image format: ${format || "unknown"}`);
  }

  const output = await encodeAvatar(data);
  await removeAvatarFiles(userId, ALL_EXTENSIONS.filter((ext) => ext !== CURRENT_EXTENSION));
  await Bun.write(avatarPath(userId, CURRENT_EXTENSION), output);

  return { extension: CURRENT_EXTENSION, contentType: CONTENT_TYPES[CURRENT_EXTENSION] };
}

export async function deleteAvatar(userId: string): Promise<void> {
  await removeAvatarFiles(userId, ALL_EXTENSIONS);
}

export async function findAvatar(userId: string): Promise<{ path: string; contentType: string } | null> {
  for (const extension of ALL_EXTENSIONS) {
    const path = avatarPath(userId, extension);
    if (await Bun.file(path).exists()) {
      return { path, contentType: CONTENT_TYPES[extension] };
    }
  }
  return null;
}

/**
 * Re-encode the avatar files written by older versions into 256x256 WebP.
 * Existing WebP files are left alone; a legacy file is dropped when a WebP for
 * the same user already exists, so the script is safe to re-run.
 */
export async function migrateAvatars(directory: string = config.avatarStorageDir): Promise<{ converted: string[]; skipped: string[]; failed: string[] }> {
  const converted: string[] = [];
  const skipped: string[] = [];
  const failed: string[] = [];

  const entries = (await readdir(directory)).filter((name) => /\.(jpg|gif|avif|webp)$/i.test(name));
  for (const name of entries.sort()) {
    const match = name.match(/^(.+)\.(jpg|gif|avif|webp)$/i);
    if (!match) continue;
    const [, userId, extension] = match;
    const lower = extension.toLowerCase();
    const target = `${directory}/${userId}.webp`;

    if (lower === "webp") {
      skipped.push(name);
      continue;
    }
    if (await Bun.file(target).exists()) {
      // A WebP is already the authoritative avatar for this user.
      await removeAvatarFiles(userId, [extension], directory);
      skipped.push(name);
      continue;
    }

    try {
      const bytes = new Uint8Array(await Bun.file(`${directory}/${name}`).arrayBuffer());
      const output = await encodeAvatar(bytes);
      await Bun.write(target, output);
      await removeAvatarFiles(userId, [extension], directory);
      converted.push(name);
    } catch (error) {
      failed.push(`${name}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return { converted, skipped, failed };
}

async function removeAvatarFiles(userId: string, extensions: string[], directory: string = config.avatarStorageDir): Promise<void> {
  await Promise.all(
    extensions.map(async (extension) => {
      try {
        await unlink(`${directory}/${userId}.${extension}`);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      }
    })
  );
}
