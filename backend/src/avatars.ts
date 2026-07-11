import sharp from "sharp";
import { unlink } from "fs/promises";
import { config } from "./config.ts";

const AVATAR_SIZE = 256;
const JPEG_QUALITY = 82;

const EXTENSIONS_BY_FORMAT: Record<string, { extension: string; contentType: string }> = {
  gif: { extension: "gif", contentType: "image/gif" },
  jpeg: { extension: "jpg", contentType: "image/jpeg" },
  png: { extension: "jpg", contentType: "image/jpeg" },
  webp: { extension: "jpg", contentType: "image/jpeg" },
};

const ALL_EXTENSIONS = ["jpg", "gif"];

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class UnsupportedImageError extends Error {}

function avatarPath(userId: string, extension: string): string {
  return `${config.avatarStorageDir}/${userId}.${extension}`;
}

export async function saveAvatar(userId: string, data: Uint8Array): Promise<{ extension: string; contentType: string }> {
  const image = sharp(data, { animated: true });
  const metadata = await image.metadata();
  const format = metadata.format ?? "";
  const target = EXTENSIONS_BY_FORMAT[format];
  if (!target) {
    throw new UnsupportedImageError(`Unsupported image format: ${format || "unknown"}`);
  }

  const output = target.extension === "gif"
    ? await image.resize(AVATAR_SIZE, AVATAR_SIZE, { fit: "cover" }).gif().toBuffer()
    : await image.resize(AVATAR_SIZE, AVATAR_SIZE, { fit: "cover" }).flatten({ background: "#ffffff" }).jpeg({ quality: JPEG_QUALITY }).toBuffer();

  await removeAvatarFiles(userId, ALL_EXTENSIONS.filter((ext) => ext !== target.extension));
  await Bun.write(avatarPath(userId, target.extension), output);

  return { extension: target.extension, contentType: target.contentType };
}

export async function findAvatar(userId: string): Promise<{ path: string; contentType: string } | null> {
  for (const extension of ALL_EXTENSIONS) {
    const path = avatarPath(userId, extension);
    if (await Bun.file(path).exists()) {
      const contentType = extension === "gif" ? "image/gif" : "image/jpeg";
      return { path, contentType };
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
