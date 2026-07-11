import { initDatabase, createUserWithActive } from "../db.ts";

function usage() {
  console.error("Usage: bun run user:add <username> <password> [--inactive] [--admin]");
}

function getArgs() {
  const args = process.argv.slice(2).filter((arg) => arg !== "--");
  const positionalArgs = args.filter((arg) => !arg.startsWith("--"));
  const flags = new Set(args.filter((arg) => arg.startsWith("--")));
  const [username, password] = positionalArgs;
  return {
    username: String(username ?? "").trim(),
    password: String(password ?? ""),
    active: !flags.has("--inactive"),
    role: flags.has("--admin") ? ("admin" as const) : ("user" as const),
  };
}

async function main() {
  await initDatabase();

  const { username, password, active, role } = getArgs();
  if (!username || !password) {
    usage();
    process.exitCode = 1;
    return;
  }

  try {
    const user = await createUserWithActive(username, password, active, { role });
    console.log(`Created user ${user.username} (${user.id}) [active=${user.active}, role=${user.role}]`);
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
