import { describe, expect, it } from "vitest";
import { databaseNameFromUrl, swapDatabaseName } from "./urls";

describe("databaseNameFromUrl", () => {
  it("extracts the database name", () => {
    expect(databaseNameFromUrl("postgres://pulse:pw@localhost:5432/pulse")).toBe("pulse");
  });

  it("handles postgresql scheme and query params", () => {
    expect(
      databaseNameFromUrl("postgresql://ci:ci@db:5432/pulse?schema=public"),
    ).toBe("pulse");
  });
});

describe("swapDatabaseName", () => {
  it("repoints the database, keeping host, port, auth and params", () => {
    const next = swapDatabaseName(
      "postgres://pulse:pw@localhost:5432/pulse?sslmode=disable",
      "postgres",
    );
    const u = new URL(next);
    expect(u.pathname).toBe("/postgres");
    expect(u.username).toBe("pulse");
    expect(u.hostname).toBe("localhost");
    expect(u.port).toBe("5432");
    expect(u.searchParams.get("sslmode")).toBe("disable");
  });

  it("repoints to a simple bare host", () => {
    expect(swapDatabaseName("postgres://pulse:pw@localhost/pulse", "postgres")).toMatch(
      /\/postgres$/,
    );
  });
});