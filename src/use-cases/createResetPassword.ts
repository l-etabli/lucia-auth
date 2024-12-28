import { createDate } from "oslo";
import { alphabet, generateRandomString } from "oslo/crypto";
import { sha256 } from "oslo/crypto";
import { encodeHex } from "oslo/encoding";

import type { AuthDependencies } from "../types";

export const createResetPassword =
  ({ authRepository, emails, resetPasswordBaseUrl }: AuthDependencies) =>
  async ({ email }: { email: string }) => {
    const user = await authRepository.user.findByEmail(email);
    if (!user || !user.emailVerifiedAt) throw new Error("Invalid email");
    await authRepository.resetPasswordToken.deleteAllForUser(user.id);
    const token = generateRandomString(40, alphabet("a-z", "0-9")); // 40 characters
    const tokenHash = encodeHex(await sha256(new TextEncoder().encode(token)));
    await authRepository.resetPasswordToken.insert({
      userId: user.id,
      tokenHash,
      expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000), // 2 hours
    });
    await emails.sendPasswordResetLink({
      email: user.email,
      verificationLink: `${resetPasswordBaseUrl}/${token}`,
    });
  };
