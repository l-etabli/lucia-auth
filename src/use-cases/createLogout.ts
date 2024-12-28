import { createBlankSessionCookie } from "../entities/session";
import type { AuthDependencies } from "../types";
import { createValidateRequest } from "./createValidateRequest";

export const createLogout = (deps: AuthDependencies) => {
  const validateRequest = createValidateRequest(deps);
  const { cookieAccessor, authRepository } = deps;
  return async () => {
    const { session } = await validateRequest();
    if (!session) throw new Error("Unauthorized");

    await authRepository.session.delete(session.id);
    cookieAccessor.set(createBlankSessionCookie());
  };
};
