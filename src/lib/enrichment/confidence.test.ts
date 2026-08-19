import { describe, expect, it } from "vitest";
import { pickIndicatorConfidence } from "./confidence";

describe("pickIndicatorConfidence", () => {
  it("keeps an analyst-locked value regardless of provider scores", () => {
    expect(pickIndicatorConfidence(80, true, [95, 45, 60])).toBe(80);
    expect(pickIndicatorConfidence(20, true, [95])).toBe(20);
  });

  it("takes the max provider score when unlocked", () => {
    expect(pickIndicatorConfidence(80, false, [95, 45, 60])).toBe(95);
    expect(pickIndicatorConfidence(10, false, [70])).toBe(70);
  });

  it("keeps the current value when there are no provider scores", () => {
    expect(pickIndicatorConfidence(50, false, [])).toBe(50);
    expect(pickIndicatorConfidence(50, true, [])).toBe(50);
  });
});