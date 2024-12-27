import { sha256 } from "@oslojs/crypto/sha2";
import {
  encodeBase32LowerCaseNoPadding,
  encodeHexLowerCase,
} from "@oslojs/encoding";
import type { Cookie } from "../types";

export type Session = {
  id: string;
  userId: string;
  expiresAt: Date;
  token: string;
};

const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const RENEWAL_THRESHOLD_MS = 15 * 24 * 60 * 60 * 1000; // 15 days

export const createSessionToken = (): string => {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return encodeBase32LowerCaseNoPadding(bytes);
};

export const generateSessionId = (token: string): string =>
  encodeHexLowerCase(sha256(new TextEncoder().encode(token)));

export const createSession = (params: {
  userId: string;
  token: string;
}): Session => ({
  id: generateSessionId(params.token),
  userId: params.userId,
  token: params.token,
  expiresAt: new Date(Date.now() + SESSION_DURATION_MS),
});

export const createSessionCookie = (token: string): Cookie => ({
  name: "session",
  value: token,
  attributes: {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: "/",
    maxAge: SESSION_DURATION_MS / 1000, // Convert to seconds
  },
});

export const shouldRenewSession = (session: Session): boolean =>
  Date.now() >= session.expiresAt.getTime() - RENEWAL_THRESHOLD_MS;

export const renewSession = (session: Session): Session => ({
  ...session,
  expiresAt: new Date(Date.now() + SESSION_DURATION_MS),
});

export const isSessionExpired = (session: Session): boolean =>
  Date.now() >= session.expiresAt.getTime();
