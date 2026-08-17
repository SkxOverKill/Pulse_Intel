// OWASP-recommended floor for modern password policy. Keeping the policy in one
// pure module means the Server Action schema and the unit tests share exactly
// one source of truth — no drift between "what the schema allows" and "what we
// test".
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 256;

/**
 * Pure policy check shared by the change-password action's schema and tests.
 * Returns a human-readable issue, or null when the new password is acceptable.
 *
 * Length-only by design: anything stronger (composition rules, breached lists)
 * belongs behind a future provider call, not in a boolean soup on the form.
 */
export function newPasswordIssue(
  password: string,
  confirmation: string,
): string | null {
  if (password !== confirmation) {
    return "Password confirmation does not match.";
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`;
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    return `Password must be at most ${PASSWORD_MAX_LENGTH} characters.`;
  }
  return null;
}