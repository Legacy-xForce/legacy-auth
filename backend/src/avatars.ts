import sharp from "sharp";
import { unlink } from "fs/promises";
import { config } from "./config.ts";

const AVATAR_SIZE = 256;
const JPEG_QUALITY = 82;
const WEBP_QUALITY = 80;

const JPEG = { extension: "jpg", contentType: "image/jpeg" };
const WEBP = { extension: "webp", contentType: "image/webp" };

const SUPPORTED_FORMATS = new Set(["gif", "jpeg", "png", "webp"]);

// "gif" is no longer written but stays here so avatars saved before the WebP switch are still served and cleaned up.
const CONTENT_TYPES_BY_EXTENSION: Record<string, string> = {
  jpg: JPEG.contentType,
  webp: WEBP.contentType,
  gif: "image/gif",
};
const ALL_EXTENSIONS = Object.keys(CONTENT_TYPES_BY_EXTENSION);

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class UnsupportedImageError extends Error {}

function avatarPath(userId: string, extension: string): string {
  return `${config.avatarStorageDir}/${userId}.${extension}`;
}

export async function saveAvatar(userId: string, data: Uint8Array): Promise<{ extension: string; contentType: string }> {
  const image = sharp(data, { animated: true });
  const metadata = await image.metadata();
  const format = metadata.format ?? "";
  if (!SUPPORTED_FORMATS.has(format)) {
    throw new UnsupportedImageError(`Unsupported image format: ${format || "unknown"}`);
  }

  const animated = (metadata.pages ?? 1) > 1;
  const target = animated ? WEBP : JPEG;

  const output = animated
    ? await image.resize(AVATAR_SIZE, AVATAR_SIZE, { fit: "cover" }).webp({ quality: WEBP_QUALITY }).toBuffer()
    : await image.resize(AVATAR_SIZE, AVATAR_SIZE, { fit: "cover" }).flatten({ background: "#ffffff" }).jpeg({ quality: JPEG_QUALITY }).toBuffer();

  await removeAvatarFiles(userId, ALL_EXTENSIONS.filter((ext) => ext !== target.extension));
  await Bun.write(avatarPath(userId, target.extension), output);

  return { extension: target.extension, contentType: target.contentType };
}

export async function deleteAvatar(userId: string): Promise<void> {
  await removeAvatarFiles(userId, ALL_EXTENSIONS);
}

export async function findAvatar(userId: string): Promise<{ path: string; contentType: string } | null> {
  for (const extension of ALL_EXTENSIONS) {
    const path = avatarPath(userId, extension);
    if (await Bun.file(path).exists()) {
      return { path, contentType: CONTENT_TYPES_BY_EXTENSION[extension] };
    }
  }
  return null;
}

async function removeAvatarFiles(userId: string, extensions: string[]): Promise<void> {
  await Promise.all(
    extensions.map(async (extension) => {
      try {
        await unlink(avatarPath(userId, extension));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
      }
    })
  );
}
