import { isWithinExpirationDate } from "oslo";
import {
  createSession,
  createSessionCookie,
  createSessionToken,
} from "../entities/session";
import type { AuthDependencies, EmailVerificationCode } from "../types";
import { createValidateRequest } from "./createValidateRequest";

export const createVerifyEmail = (deps: AuthDependencies) => {
  const validateRequest = createValidateRequest(deps);

  return async ({
    candidateCode,
  }: {
    candidateCode: string;
  }) => {
    const { authRepository, cookieAccessor } = deps;
    const { user } = await validateRequest();
    if (!user) throw new Error("Unauthorized");

    const emailVerification =
      await authRepository.emailVerificationCode.getByUserId(user.id);
    if (
      !isCodeValid({
        dbEmailVerification: emailVerification,
        user,
        candidateCode,
      })
    )
      throw new Error("Bad request");

    await authRepository.session.deleteAllForUser(user.id);

    await authRepository.user.markEmailVerified({
      verifiedAt: new Date(),
      userId: user.id,
    });

    const sessionToken = createSessionToken();
    const session = await createSession({
      userId: user.id,
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
};

const isCodeValid = ({
  dbEmailVerification,
  candidateCode,
  user,
}: {
  dbEmailVerification: EmailVerificationCode | undefined;
  candidateCode: string;
  user: { id: string };
}): boolean => {
  if (!dbEmailVerification || candidateCode !== dbEmailVerification.code)
    return false;

  if (!isWithinExpirationDate(dbEmailVerification.expiresAt)) return false;

  if (dbEmailVerification.userId !== user.id) return false;

  return true;
};
