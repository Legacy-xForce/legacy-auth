import { migrateAvatars } from "../avatars.ts";
import { config } from "../config.ts";

const directory = process.argv[2] ?? config.avatarStorageDir;
let result;
try {
  result = await migrateAvatars(directory);
} catch (error) {
  if ((error as NodeJS.ErrnoException).code === "ENOENT") {
    console.error(`Avatar storage directory does not exist: ${directory}`);
    process.exit(1);
  }
  throw error;
}

console.log(`Avatar migration in ${directory}`);
console.log(`  converted to WebP: ${result.converted.length}`);
for (const name of result.converted) console.log(`    ${name}`);
console.log(`  already WebP / legacy copy removed: ${result.skipped.length}`);
for (const name of result.skipped) console.log(`    ${name}`);
console.log(`  failed: ${result.failed.length}`);
for (const message of result.failed) console.error(`    ${message}`);

if (result.failed.length > 0) process.exitCode = 1;
