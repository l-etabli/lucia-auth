import { isWithinExpirationDate } from "oslo";
import { sha256 } from "oslo/crypto";
import { encodeHex } from "oslo/encoding";
import { Argon2id } from "oslo/password";

import {
  createSession,
  createSessionCookie,
  createSessionToken,
} from "../entities/session";
import type { AuthDependencies } from "../types";

export const createChangePassword =
  ({ authRepository, hashingParams, cookieAccessor }: AuthDependencies) =>
  async ({
    newPassword,
    resetPasswordToken,
  }: {
    email: string;
    newPassword: string;
    resetPasswordToken: string;
  }) => {
    const tokenHash = encodeHex(
      await sha256(new TextEncoder().encode(resetPasswordToken)),
    );
    const token =
      await authRepository.resetPasswordToken.getByTokenHash(tokenHash);

    if (token) {
      await authRepository.resetPasswordToken.deleteByTokenHash(tokenHash);
    }

    if (!token || !isWithinExpirationDate(token.expiresAt)) {
      throw new Error("Invalid token");
    }

    await authRepository.session.deleteAllForUser(token.userId);

    const passwordHash = await new Argon2id(hashingParams).hash(newPassword);

    await authRepository.user.updatePasswordHash({
      userId: token.userId,
      passwordHash,
    });

    const sessionToken = createSessionToken();
    const session = await createSession({
      userId: token.userId,
      token: sessionToken,
    });
    await authRepository.session.insert(session);

    cookieAccessor.set(
      createSessionCookie({
        token: sessionToken,
        expiresAt: session.expiresAt,
      }),
    );
  };
