export const sanitizeEmail = (email: string): string => {
  const sanitized = email.trim().toLowerCase();
  if (!isValidEmail(sanitized)) {
    throw new Error("Invalid email format");
  }
  return sanitized;
};

const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
};
