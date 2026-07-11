import { initDatabase, findUserByUsername, revokeAllRefreshTokensForUser, updateUserActive } from "../db.ts";
import { invalidateCachedUser } from "../cache.ts";

function usage() {
  console.error("Usage: bun run user:set-active <username> <true|false>");
}

function parseActive(value: string) {
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "on", "active"].includes(normalized)) return true;
  if (["false", "0", "no", "off", "inactive", "disabled"].includes(normalized)) return false;
  return null;
}

async function main() {
  await initDatabase();

  const [rawUsername, rawActive] = process.argv.slice(2).filter((arg) => arg !== "--");
  const username = String(rawUsername ?? "").trim();
  const active = parseActive(String(rawActive ?? ""));

  if (!username || active === null) {
    usage();
    process.exitCode = 1;
    return;
  }

  try {
    const existing = await findUserByUsername(username);
    if (!existing) {
      console.error(`User not found: ${username}`);
      process.exitCode = 1;
      return;
    }

    const user = await updateUserActive(existing.id, active);
    if (!user) {
      console.error(`Failed to update user: ${username}`);
      process.exitCode = 1;
      return;
    }

    if (!active) {
      await revokeAllRefreshTokensForUser(user.id);
    }
    invalidateCachedUser(user.username);

    console.log(`Updated user ${user.username} (${user.id}) [active=${user.active}]`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Failed to update user: ${message}`);
    process.exitCode = 1;
  }
}

await main();
