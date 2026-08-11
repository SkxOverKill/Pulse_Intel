import { describe, expect, it } from "vitest";
import {
  parseBooleanParam,
  parseIndicatorType,
  parsePageParams,
  parseSeverity,
} from "./query";

describe("API query parsing", () => {
  it("accepts bounded pagination", () => {
    const parsed = parsePageParams(new URLSearchParams("page=2&pageSize=50"), {
      pageSize: 25,
      maxPageSize: 100,
    });

    expect(parsed).toEqual({ ok: true, value: { page: 2, pageSize: 50 } });
  });

  it("rejects invalid pagination", () => {
    const parsed = parsePageParams(new URLSearchParams("page=0&pageSize=500"), {
      pageSize: 25,
      maxPageSize: 100,
    });

    expect(parsed.ok).toBe(false);
  });

  it("accepts known indicator and severity enums", () => {
    expect(parseIndicatorType("IPV4")).toEqual({ ok: true, value: "IPV4" });
    expect(parseSeverity("HIGH")).toEqual({ ok: true, value: "HIGH" });
  });

  it("rejects unknown enum values before Prisma sees them", () => {
    expect(parseIndicatorType("ip")).toMatchObject({ ok: false });
    expect(parseSeverity("SEVERE")).toMatchObject({ ok: false });
  });

  it("parses booleans strictly", () => {
    expect(parseBooleanParam("true", "active")).toEqual({ ok: true, value: true });
    expect(parseBooleanParam("false", "active")).toEqual({ ok: true, value: false });
    expect(parseBooleanParam("yes", "active")).toMatchObject({ ok: false });
  });
});
