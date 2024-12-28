import type { Session } from "../entities/session";
import {
  SESSION_COOKIE_NAME,
  createBlankSessionCookie,
  createSessionCookie,
  validateSession,
} from "../entities/session";
import type { AuthDependencies } from "../types";
import type { User } from "../types";

export const createValidateRequest =
  ({ authRepository, cookieAccessor }: AuthDependencies) =>
  async (): Promise<
    { user: User; session: Session } | { user: null; session: null }
  > => {
    const sessionToken = cookieAccessor.get(SESSION_COOKIE_NAME)?.value ?? null;
    if (!sessionToken) {
      return { user: null, session: null };
    }

    const result = await validateSession({
      token: sessionToken,
      sessionRepository: authRepository.session,
    });

    if (!result.session) {
      cookieAccessor.set(createBlankSessionCookie());
      return { user: null, session: null };
    }

    const user = await authRepository.user.findById(result.session.userId);
    if (!user) {
      return { user: null, session: null };
    }

    if (result.fresh) {
      cookieAccessor.set(
        createSessionCookie({
          token: result.session.token,
          expiresAt: result.session.expiresAt,
        }),
      );
    }

    return { user, session: result.session };
  };
