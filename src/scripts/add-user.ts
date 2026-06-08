import Postgres from "postgres";
import bcrypt from "bcryptjs";
import { config } from "../config.ts";

function usage() {
  console.error("Usage: bun run user:add <username> <password>");
}

function getArgs() {
  const args = process.argv.slice(2).filter((arg) => arg !== "--");
  const [username, password] = args;
  return {
    username: String(username ?? "").trim(),
    password: String(password ?? ""),
  };
}

async function main() {
  const { username, password } = getArgs();
  if (!username || !password) {
    usage();
    process.exitCode = 1;
    return;
  }

  const sql = Postgres(config.dbUrl, { max: 1 });

  try {
    const passwordHash = await bcrypt.hash(password, config.bcryptSaltRounds);
    const result = await sql<{ id: string; username: string }[]>`
      INSERT INTO users (username, password_hash)
      VALUES (${username}, ${passwordHash})
      RETURNING id, username;
    `;

    const user = result[0];
    console.log(`Created user ${user.username} (${user.id})`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.toLowerCase().includes("unique")) {
      console.error(`Username already exists: ${username}`);
    } else {
      console.error(`Failed to create user: ${message}`);
    }
    process.exitCode = 1;
  } finally {
    await sql.end({ timeout: 5 });
  }
}

await main();
