import jwt from "jsonwebtoken";
import { config } from "./config.ts";
import { createHash, randomUUID } from "crypto";
import { getPrivateKey, getPublicKey, getKid } from "./keys.ts";

export type AccessTokenPayload = {
  sub: string;
  username: string;
  type: "access";
};

export type RefreshTokenPayload = {
  sub: string;
  username: string;
  jti: string;
  type: "refresh";
};

export function signAccessToken(payload: { sub: string; username: string }) {
  return jwt.sign(
    {
      sub: payload.sub,
      username: payload.username,
      type: "access",
    },
    getPrivateKey(),
    {
      algorithm: "ES256",
      expiresIn: config.accessTokenTtlSeconds,
      keyid: getKid(),
    }
  );
}

export function signRefreshToken(payload: { sub: string; username: string }) {
  const jti = randomUUID();
  return {
    token: jwt.sign(
      {
        sub: payload.sub,
        username: payload.username,
        jti,
        type: "refresh",
      },
      config.jwtSecret,
      {
        algorithm: "HS256",
        expiresIn: config.refreshTokenTtlSeconds,
      }
    ),
    jti,
  };
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  return jwt.verify(token, getPublicKey()) as AccessTokenPayload;
}

export function verifyRefreshToken(token: string): RefreshTokenPayload {
  const payload = jwt.verify(token, config.jwtSecret) as RefreshTokenPayload;
  if (payload.type !== "refresh") {
    throw new Error("Invalid refresh token type");
  }
  return payload;
}

export function getRefreshTokenExpiresAt(): Date {
  return new Date(Date.now() + config.refreshTokenTtlSeconds * 1000);
}
