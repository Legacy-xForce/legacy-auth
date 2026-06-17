import { createUser } from "../db.ts";

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

  try {
    const user = await createUser(username, password);
    console.log(`Created user ${user.username} (${user.id})`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.toLowerCase().includes("unique")) {
      console.error(`Username already exists: ${username}`);
    } else {
      console.error(`Failed to create user: ${message}`);
    }
    process.exitCode = 1;
  }
}

await main();
