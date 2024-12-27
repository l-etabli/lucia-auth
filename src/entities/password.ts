/**
 * Validates and sanitizes a password
 * Requirements:
 * - Minimum length of 8 characters
 * - At least one number
 * - At least one uppercase character
 * @throws Error if password doesn't meet requirements
 */
export const sanitizePassword = (password: string): string => {
  const trimmedPassword = password.trim();

  if (trimmedPassword.length < 8) {
    throw new Error("Password must be at least 8 characters long");
  }

  if (!/\d/.test(trimmedPassword)) {
    throw new Error("Password must contain at least one number");
  }

  if (!/[A-Z]/.test(trimmedPassword)) {
    throw new Error("Password must contain at least one uppercase character");
  }

  return trimmedPassword;
};
