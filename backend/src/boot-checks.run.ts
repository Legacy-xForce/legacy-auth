// Imported first by index.ts: modules evaluate in import order, so this throws
// before keys.ts gets the chance to generate an ephemeral signing key.
import { assertBootConfig } from "./boot-checks.ts";

assertBootConfig();
