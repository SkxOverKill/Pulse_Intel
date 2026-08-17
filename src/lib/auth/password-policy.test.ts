import { describe, expect, it } from "vitest";
import {
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  newPasswordIssue,
} from "@/lib/auth/password-policy";

describe("newPasswordIssue", () => {
  it("accepts a strong password that matches its confirmation", () => {
    expect(newPasswordIssue("correct-horse-battery-staple", "correct-horse-battery-staple")).toBeNull();
  });

  it("rejects a password shorter than the minimum", () => {
    const short = "x".repeat(PASSWORD_MIN_LENGTH - 1);
    expect(newPasswordIssue(short, short)).toBe(
      `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`,
    );
  });

  it("rejects a password longer than the maximum", () => {
    const long = "x".repeat(PASSWORD_MAX_LENGTH + 1);
    expect(newPasswordIssue(long, long)).toBe(
      `Password must be at most ${PASSWORD_MAX_LENGTH} characters.`,
    );
  });

  it("accepts a password exactly at the minimum", () => {
    const at = "x".repeat(PASSWORD_MIN_LENGTH);
    expect(newPasswordIssue(at, at)).toBeNull();
  });

  it("accepts a password exactly at the maximum", () => {
    const at = "x".repeat(PASSWORD_MAX_LENGTH);
    expect(newPasswordIssue(at, at)).toBeNull();
  });

  it("rejects when the confirmation does not match", () => {
    // Mismatch is reported before length so the user fixes the likely typo.
    expect(newPasswordIssue("a-valid-password-here", "a-different-password")).toBe(
      "Password confirmation does not match.",
    );
  });

  it("reports the mismatch even for short passwords", () => {
    expect(newPasswordIssue("a", "b")).toBe("Password confirmation does not match.");
  });

  it("treats whitespace as significant", () => {
    expect(newPasswordIssue("password-with-space ", "password-with-space ")).toBeNull();
  });
});