import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "crypto";
import { config } from "./config.ts";

type JwkPublicKey = { kty: string; crv: string; x: string; y: string };

let privateKey: KeyObject;
let publicKey: KeyObject;
let kid: string;

function computeThumbprint(jwk: JwkPublicKey): string {
  // RFC 7638: SHA-256 of canonical JSON with required members in lexicographic order
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash("sha256").update(canonical).digest("base64url");
}

if (config.jwtPrivateKeyPem) {
  // .env files often store newlines as literal \n — normalize before parsing
  const pem = config.jwtPrivateKeyPem.replace(/\\n/g, "\n");
  privateKey = createPrivateKey(pem);
} else {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  privateKey = pair.privateKey;
  console.warn("[keys] JWT_PRIVATE_KEY not set — using ephemeral key pair; tokens will be invalidated on restart");
}

publicKey = createPublicKey(privateKey);
const jwk = publicKey.export({ format: "jwk" }) as JwkPublicKey;
kid = config.jwtKeyId || computeThumbprint(jwk);

export function getPrivateKey(): KeyObject {
  return privateKey;
}

export function getPublicKey(): KeyObject {
  return publicKey;
}

export function getKid(): string {
  return kid;
}

export function getJwks() {
  return {
    keys: [
      {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        use: "sig",
        alg: "ES256",
        kid,
      },
    ],
  };
}
