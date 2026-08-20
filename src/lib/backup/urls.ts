/**
 * Postgres connection-string helpers for the backup/restore tooling.
 * Pure string/URL work so the smoke-test script's riskiest logic is unit-tested
 * without a live database.
 */

export function databaseNameFromUrl(databaseUrl: string): string {
  return decodeURIComponent(new URL(databaseUrl).pathname.replace(/^\//, "").split("/")[0]);
}

/**
 * Returns the same connection string pointed at a different database, keeping
 * auth, host, port, and query params intact. Used to reach the `postgres`
 * maintenance database to CREATE/DROP the scratch DB, and to target the
 * restore at the scratch database itself.
 */
export function swapDatabaseName(databaseUrl: string, database: string): string {
  const url = new URL(databaseUrl);
  url.pathname = `/${database}`;
  return url.toString();
}