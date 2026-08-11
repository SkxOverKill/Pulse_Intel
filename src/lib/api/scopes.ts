/**
 * Known API key scopes. Client-safe (no `db`, no `server-only`) so the
 * Settings UI can render the checkbox list from the same source the routes
 * check against — one list, never two to keep in sync.
 */
export const API_SCOPES = [
  { value: "indicators:read", label: "Read indicators" },
  { value: "actors:read", label: "Read threat actors" },
] as const;

export type ApiScope = (typeof API_SCOPES)[number]["value"];
