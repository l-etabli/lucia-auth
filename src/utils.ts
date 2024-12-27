/**
 * Sanitizes an email address by trimming whitespace and converting to lowercase
 */
export const sanitizeEmail = (email: string): string => {
  return email.trim().toLowerCase();
};
