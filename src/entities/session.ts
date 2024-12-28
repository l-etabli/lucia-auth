import { sha256 } from "oslo/crypto";
import { base32, encodeHex } from "oslo/encoding";
import type { Cookie } from "../types";

export type Session = {
  id: string;
  userId: string;
  expiresAt: Date;
  token: string;
};

export type ValidateSessionResult = {
  session: Session | null;
  fresh: boolean;
};

const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const RENEWAL_THRESHOLD_MS = 15 * 24 * 60 * 60 * 1000; // 15 days
export const SESSION_COOKIE_NAME = "auth_session";

export const createSessionToken = (): string => {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32.encode(bytes, { includePadding: false });
};

export const generateSessionId = async (token: string): Promise<string> => {
  const hash = await sha256(new TextEncoder().encode(token));
  return encodeHex(hash);
};

export const createSession = async (params: {
  userId: string;
  token: string;
}): Promise<Session> => ({
  id: await generateSessionId(params.token),
  userId: params.userId,
  token: params.token,
  expiresAt: new Date(Date.now() + SESSION_DURATION_MS),
});

export const shouldRenewSession = (session: Session): boolean =>
  Date.now() >= session.expiresAt.getTime() - RENEWAL_THRESHOLD_MS;

export const renewSession = (session: Session): Session => ({
  ...session,
  expiresAt: new Date(Date.now() + SESSION_DURATION_MS),
});

export const isSessionExpired = (session: Session): boolean =>
  Date.now() >= session.expiresAt.getTime();

export const validateSession = async (params: {
  token: string;
  sessionRepository: {
    findById: (id: string) => Promise<Session | undefined>;
    update: (session: Session) => Promise<void>;
  };
}): Promise<ValidateSessionResult> => {
  const sessionId = await generateSessionId(params.token);
  const session = await params.sessionRepository.findById(sessionId);

  if (!session || isSessionExpired(session)) {
    return { session: null, fresh: false };
  }

  if (shouldRenewSession(session)) {
    const renewedSession = renewSession(session);
    await params.sessionRepository.update(renewedSession);
    return { session: renewedSession, fresh: true };
  }

  return { session, fresh: false };
};

export const createSessionCookie = (params: {
  token: string;
  expiresAt: Date;
}): Cookie => ({
  name: SESSION_COOKIE_NAME,
  value: params.token,
  attributes: {
    expires: params.expiresAt,
    httpOnly: true,
    secure: true,
    path: "/",
  },
});

export const createBlankSessionCookie = (): Cookie => ({
  name: SESSION_COOKIE_NAME,
  value: "",
  attributes: {
    expires: new Date(0),
    httpOnly: true,
    secure: true,
    path: "/",
  },
});
