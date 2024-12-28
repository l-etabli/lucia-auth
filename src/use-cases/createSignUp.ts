import { createDate } from "oslo";
import { alphabet, generateRandomString } from "oslo/crypto";
import { Argon2id } from "oslo/password";

import { sanitizeEmail } from "../entities/email";
import { sanitizePassword } from "../entities/password";
import {
  createSession,
  createSessionCookie,
  createSessionToken,
} from "../entities/session";
import type { AuthDependencies, EmailAndPassword } from "../types";

export const createSignUp =
  ({
    authRepository,
    emails,
    hashingParams,
    cookieAccessor,
  }: AuthDependencies) =>
  async (params: EmailAndPassword) => {
    const email = sanitizeEmail(params.email);
    const password = sanitizePassword(params.password);
    const passwordHash = await new Argon2id(hashingParams).hash(password);
    const userId = generateRandomString(16, alphabet("a-z", "0-9"));
    const now = new Date();

    try {
      await authRepository.user.insert({
        id: userId,
        email,
        passwordHash,
        emailVerifiedAt: null,
        createdAt: now,
        updatedAt: now,
        isActive: true,
      });

      const emailValidationCode = generateRandomString(8, alphabet("0-9"));

      await authRepository.emailVerificationCode.insert({
        code: emailValidationCode,
        userId: userId,
        email,
        expiresAt: new Date(Date.now() + 3 * 60 * 60 * 1000), // 3 hours
      });

      await emails.sendSignedUpSuccessfully({
        email,
        code: emailValidationCode,
      });

      const sessionToken = createSessionToken();
      const session = await createSession({ userId, token: sessionToken });
      await authRepository.session.insert(session);

      cookieAccessor.set(
        createSessionCookie({
          token: sessionToken,
          expiresAt: session.expiresAt,
        }),
      );
    } catch {
      // db error, email taken, etc
      throw new Error("Email already used");
    }
  };
