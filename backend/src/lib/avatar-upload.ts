import { config } from "../config.ts";
import { saveAvatar, UnsupportedImageError } from "../avatars.ts";
import type { Ctx } from "./context.ts";

/**
 * The multipart/image validation and error mapping shared by the user's own
 * avatar endpoint and the admin's "upload on behalf of" endpoint. The caller
 * has already checked that the target user exists and may be changed.
 */
export async function performAvatarUpload(c: Ctx, userId: string): Promise<Response> {
  let formData: FormData;
  try { formData = await c.req.formData(); }
  catch { return c.json({ error: "Request must be multipart/form-data" } as any, 400); }

  const file = formData.get("file");
  if (!(file instanceof Blob) || file.size === 0) return c.json({ error: "file is required" } as any, 400);
  if (file.size > config.avatarMaxUploadBytes) {
    return c.json({ error: `file exceeds maximum size of ${config.avatarMaxUploadBytes} bytes` } as any, 413);
  }

  const bytes = new Uint8Array(await file.arrayBuffer());
  try {
    const saved = await saveAvatar(userId, bytes);
    return c.json({ success: true, content_type: saved.contentType } as any, 200);
  } catch (error) {
    if (error instanceof UnsupportedImageError) return c.json({ error: error.message } as any, 400);
    return c.json({ error: "Invalid or corrupted image" } as any, 400);
  }
}
