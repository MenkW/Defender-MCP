import { getAccessToken, getGraphAccessToken, getWdatpAccessToken } from "./auth.js";

const MTP_BASE_URL   = "https://api.security.microsoft.com/api";
const WDATP_BASE_URL = "https://api.securitycenter.microsoft.com/api";
const GRAPH_SECURITY_BASE_URL = (
  process.env.DEFENDER_GRAPH_SECURITY_BASE_URL ?? "https://graph.microsoft.com/v1.0/security"
).replace(/\/+$/, "");

export interface ApiResponse<T = unknown> {
  value?: T[];
  "@odata.context"?: string;
  "@odata.nextLink"?: string;
  [key: string]: unknown;
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  queryParams?: Record<string, string | number | boolean | undefined>;
  /** Set to true for Alerts, Machines, Files, IPs, URLs, Users, and other WDATP routes */
  useWdatp?: boolean;
  /** Set to true for Microsoft Graph Security API routes */
  useGraph?: boolean;
}

function buildQueryString(params?: Record<string, string | number | boolean | undefined>): string {
  if (!params) return "";

  const filtered = Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== "")
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);

  return filtered.length > 0 ? `?${filtered.join("&")}` : "";
}

export async function defenderApiRequest<T = unknown>(
  endpoint: string,
  options: RequestOptions = {}
): Promise<T> {
  const { method = "GET", body, queryParams, useGraph = false, useWdatp = false } = options;

  const token = useGraph
    ? await getGraphAccessToken()
    : useWdatp
      ? await getWdatpAccessToken()
      : await getAccessToken();
  const baseUrl = useGraph ? GRAPH_SECURITY_BASE_URL : useWdatp ? WDATP_BASE_URL : MTP_BASE_URL;
  const url     = `${baseUrl}${endpoint}${buildQueryString(queryParams)}`;

  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };

  const fetchOptions: RequestInit = {
    method,
    headers,
  };

  if (body && (method === "POST" || method === "PATCH")) {
    fetchOptions.body = JSON.stringify(body);
  }

  const response = await fetch(url, fetchOptions);

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Defender API error (${response.status}): ${errorText}`);
  }

  // Handle empty responses (e.g., DELETE operations)
  const text = await response.text();
  if (!text) {
    return {} as T;
  }

  return JSON.parse(text) as T;
}

export async function defenderApiRequestPaginated<T = unknown>(
  endpoint: string,
  options: RequestOptions = {},
  maxResults?: number
): Promise<T[]> {
  const results: T[] = [];
  let nextLink: string | undefined;
  let currentUrl = endpoint;
  const baseUrl = options.useGraph
    ? GRAPH_SECURITY_BASE_URL
    : options.useWdatp
      ? WDATP_BASE_URL
      : MTP_BASE_URL;

  do {
    const response = await defenderApiRequest<ApiResponse<T>>(
      nextLink ? nextLink.replace(baseUrl, "") : currentUrl,
      nextLink
        ? { method: options.method, useGraph: options.useGraph, useWdatp: options.useWdatp }
        : options
    );

    if (response.value) {
      results.push(...response.value);
    }

    nextLink = response["@odata.nextLink"];

    if (maxResults && results.length >= maxResults) {
      return results.slice(0, maxResults);
    }
  } while (nextLink);

  return results;
}
