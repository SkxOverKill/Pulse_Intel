import { NextResponse } from "next/server";
import {
  IndicatorType,
  Severity,
  Motivation,
  CampaignStatus,
} from "@/generated/prisma/enums";

export type ParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; response: NextResponse };

export type PageParams = {
  page: number;
  pageSize: number;
};

function enumValues<T extends Record<string, string>>(values: T): Set<T[keyof T]> {
  return new Set(Object.values(values) as T[keyof T][]);
}

const INDICATOR_TYPES = enumValues(IndicatorType);
const SEVERITIES = enumValues(Severity);
const MOTIVATIONS = enumValues(Motivation);
const CAMPAIGN_STATUSES = enumValues(CampaignStatus);

export function parsePageParams(
  params: URLSearchParams,
  defaults: { pageSize: number; maxPageSize: number },
): ParseResult<PageParams> {
  const page = Number(params.get("page") ?? 1);
  const pageSize = Number(params.get("pageSize") ?? defaults.pageSize);

  if (!Number.isInteger(page) || page < 1) {
    return badRequest("page must be a positive integer.");
  }
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > defaults.maxPageSize) {
    return badRequest(`pageSize must be between 1 and ${defaults.maxPageSize}.`);
  }

  return { ok: true, value: { page, pageSize } };
}

export function parseBooleanParam(
  value: string | null,
  name: string,
): ParseResult<boolean | null> {
  if (value === null) return { ok: true, value: null };
  if (value === "true") return { ok: true, value: true };
  if (value === "false") return { ok: true, value: false };
  return badRequest(`${name} must be true or false.`);
}

export function parseIndicatorType(value: string | null): ParseResult<IndicatorType | null> {
  return parseEnum(value, "type", INDICATOR_TYPES);
}

export function parseSeverity(value: string | null): ParseResult<Severity | null> {
  return parseEnum(value, "severity", SEVERITIES);
}

export function parseMotivation(value: string | null): ParseResult<Motivation | null> {
  return parseEnum(value, "motivation", MOTIVATIONS);
}

export function parseCampaignStatus(value: string | null): ParseResult<CampaignStatus | null> {
  return parseEnum(value, "status", CAMPAIGN_STATUSES);
}

function parseEnum<T extends string>(
  value: string | null,
  name: string,
  allowed: Set<T>,
): ParseResult<T | null> {
  if (!value) return { ok: true, value: null };
  if (allowed.has(value as T)) return { ok: true, value: value as T };
  return badRequest(`${name} must be one of: ${[...allowed].join(", ")}.`);
}

function badRequest<T>(message: string): ParseResult<T> {
  return {
    ok: false,
    response: NextResponse.json({ error: message }, { status: 400 }),
  };
}
