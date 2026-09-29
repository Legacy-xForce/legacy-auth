import * as crypto from "crypto";
import { config } from "./config.ts";
import { UserRecord } from "./types.ts";
import {
  savePasskeyCredential,
  findPasskeyCredentialWithUser,
  findPasskeyCredentialsByUserId,
  findPasskeyCredentialsByUsername,
  updatePasskeyCounter,
  deletePasskeyCredential,
  saveRefreshToken,
} from "./db.ts";
import { signAccessToken, signRefreshToken, getRefreshTokenExpiresAt } from "./jwt.ts";

interface StoredChallenge {
  challenge: string;
  userId?: string;
  expiresAt: number;
}

const challenges = new Map<string, StoredChallenge>();

// Periodically prune expired challenges
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of challenges.entries()) {
    if (value.expiresAt < now) {
      challenges.delete(key);
    }
  }
}, 60000).unref();

function generateRandomChallenge(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function decodeBase64(value: unknown, fieldName: string): Buffer {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty base64 string`);
  }

  let normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  normalized += "=".repeat((4 - (normalized.length % 4)) % 4);
  try {
    return Buffer.from(normalized, "base64");
  } catch {
    throw new Error(`Invalid ${fieldName}`);
  }
}

export type PasskeyRegisterVerifyPayload = {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    attestationObject?: string;
    publicKey?: string;
    transports?: string[];
  };
  deviceName?: string;
};

export type PasskeyLoginVerifyPayload = {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
};

export async function generateRegisterOptions(user: UserRecord) {
  const challenge = generateRandomChallenge();

  challenges.set(`reg_${user.id}`, {
    challenge,
    userId: user.id,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  challenges.set(`chal_${challenge}`, {
    challenge,
    userId: user.id,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  return {
    challenge,
    rp: {
      name: "Legacy Auth",
    },
    user: {
      id: Buffer.from(user.id).toString("base64url"),
      name: user.username,
      displayName: user.username,
    },
    pubKeyCredParams: [
      { alg: -7, type: "public-key" }, // ES256
      { alg: -257, type: "public-key" }, // RS256
    ],
    timeout: 60000,
    attestation: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      requireResidentKey: false,
      userVerification: "preferred",
    },
  };
}

export async function verifyRegister(userId: string, dto: PasskeyRegisterVerifyPayload) {
  if (!dto || typeof dto !== "object" || !dto.id || !dto.response) {
    throw new Error("Invalid registration payload");
  }

  const stored = challenges.get(`reg_${userId}`);
  if (!stored) {
    throw new Error("Registration challenge not found or expired");
  }

  let parsedClientData: { challenge?: string; type?: string };
  try {
    const rawJson = decodeBase64(dto.response.clientDataJSON, "clientDataJSON").toString("utf8");
    parsedClientData = JSON.parse(rawJson);
  } catch {
    throw new Error("Invalid clientDataJSON: failed to decode JSON");
  }

  if (parsedClientData.type !== "webauthn.create" || parsedClientData.challenge !== stored.challenge) {
    throw new Error("Challenge mismatch");
  }

  challenges.delete(`reg_${userId}`);
  challenges.delete(`chal_${stored.challenge}`);

  if (!dto.response.publicKey) {
    throw new Error("Registration response did not include a public key");
  }

  const publicKey = dto.response.publicKey;
  const deviceName = dto.deviceName?.trim() || "Biometric Passkey";

  const credential = await savePasskeyCredential(dto.id, userId, publicKey, deviceName);
  return { success: true, credentialId: credential.id, deviceName: credential.device_name };
}

export async function generateLoginOptions(username?: string) {
  const challenge = generateRandomChallenge();
  let allowCredentials: { id: string; type: "public-key" }[] = [];

  if (username) {
    const creds = await findPasskeyCredentialsByUsername(username);
    allowCredentials = creds.map((c) => ({
      id: c.id,
      type: "public-key" as const,
    }));
  }

  challenges.set(`chal_${challenge}`, {
    challenge,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  return {
    challenge,
    timeout: 60000,
    userVerification: "preferred",
    allowCredentials,
  };
}

export async function verifyLogin(dto: PasskeyLoginVerifyPayload) {
  if (!dto || typeof dto !== "object" || !dto.id || !dto.response) {
    throw new Error("Invalid login payload");
  }

  let parsedClientData: { challenge?: string; type?: string };
  try {
    const rawJson = decodeBase64(dto.response.clientDataJSON, "clientDataJSON").toString("utf8");
    parsedClientData = JSON.parse(rawJson);
  } catch {
    throw new Error("Invalid clientDataJSON: failed to decode JSON");
  }

  if (parsedClientData.type !== "webauthn.get") {
    throw new Error("Invalid WebAuthn response type");
  }

  const challengeKey = `chal_${parsedClientData.challenge ?? ""}`;
  const stored = challenges.get(challengeKey);
  if (!stored) {
    throw new Error("Authentication challenge expired or invalid");
  }
  challenges.delete(challengeKey);

  const credential = await findPasskeyCredentialWithUser(dto.id);
  if (!credential) {
    throw new Error("Unknown passkey credential");
  }

  if (!credential.user.active) {
    const err = new Error("Account disabled");
    (err as any).statusCode = 403;
    throw err;
  }

  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey({
      key: decodeBase64(credential.public_key, "publicKey"),
      format: "der",
      type: "spki",
    });
  } catch {
    throw new Error("Stored passkey public key is invalid");
  }

  const clientDataHash = crypto
    .createHash("sha256")
    .update(decodeBase64(dto.response.clientDataJSON, "clientDataJSON"))
    .digest();
  const authenticatorData = decodeBase64(dto.response.authenticatorData, "authenticatorData");
  if (authenticatorData.length < 37 || (authenticatorData[32] & 0x01) === 0) {
    throw new Error("Passkey user verification failed");
  }

  const validSignature = crypto.verify(
    "sha256",
    Buffer.concat([authenticatorData, clientDataHash]),
    publicKey,
    decodeBase64(dto.response.signature, "signature")
  );
  if (!validSignature) {
    throw new Error("Invalid passkey signature");
  }

  const counter = authenticatorData.readUInt32BE(33);
  if (counter !== 0 && counter <= Number(credential.counter)) {
    throw new Error("Passkey counter replay detected");
  }
  await updatePasskeyCounter(credential.id, counter);

  const user = credential.user;
  const accessToken = signAccessToken({
    sub: user.id,
    username: user.username,
    role: user.role,
    scopes: user.scopes,
  });
  const refreshTokenMeta = signRefreshToken({ sub: user.id, username: user.username });
  await saveRefreshToken(user.id, refreshTokenMeta.jti, refreshTokenMeta.token, getRefreshTokenExpiresAt());

  return {
    access_token: accessToken,
    refresh_token: refreshTokenMeta.token,
    expires_in: config.accessTokenTtlSeconds,
    refresh_expires_in: config.refreshTokenTtlSeconds,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      active: user.active,
      scopes: user.scopes,
    },
  };
}

export async function listCredentials(userId: string) {
  const creds = await findPasskeyCredentialsByUserId(userId);
  return creds.map((c) => ({
    id: c.id,
    deviceName: c.device_name || "Passkey",
    createdAt: c.created_at,
  }));
}

export async function deleteCredential(id: string, userId: string) {
  const deleted = await deletePasskeyCredential(id, userId);
  if (!deleted) {
    const err = new Error("Passkey not found");
    (err as any).statusCode = 404;
    throw err;
  }
  return { success: true };
}
