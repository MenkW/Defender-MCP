import { z } from "zod";
import { defenderApiRequest } from "../api-client.js";

// Schema definitions
export const RunAdvancedQuerySchema = z.object({
  query: z
    .string()
    .describe(
      "The Kusto Query Language (KQL) query to execute. Max 100,000 rows returned."
    ),
  timespan: z
    .string()
    .optional()
    .describe(
      "Optional ISO 8601 query timespan (for example P90D or 2026-07-01T00:00:00Z/2026-10-01T00:00:00Z). Microsoft Graph defaults to P30D."
    ),
  workspaceId: z
    .string()
    .uuid()
    .optional()
    .describe(
      "Optional Microsoft Sentinel Log Analytics workspace GUID. If omitted, Microsoft Graph uses the caller's primary workspace."
    ),
});

export const RunXdrHuntingQuerySchema = z.object({
  query: z
    .string()
    .describe(
      "The Kusto Query Language (KQL) query to execute against the unified Microsoft Defender XDR and Microsoft Sentinel advanced hunting schema. Max 100,000 rows returned."
    ),
  timespan: z
    .string()
    .optional()
    .describe(
      "Optional ISO 8601 query timespan (for example P90D or 2026-07-01T00:00:00Z/2026-10-01T00:00:00Z). Microsoft Graph defaults to P30D."
    ),
  workspaceId: z
    .string()
    .uuid()
    .optional()
    .describe(
      "Optional Microsoft Sentinel Log Analytics workspace GUID. If omitted, Microsoft Graph uses the caller's primary workspace."
    ),
});

export const GetHuntingSchemaSchema = z.object({
  tableName: z
    .string()
    .regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "tableName must be a single KQL table identifier")
    .describe(
      "Defender XDR or Microsoft Sentinel advanced hunting table name whose columns should be returned."
    ),
});

// Tool implementations

interface UnifiedHuntingQueryParams {
  query: string;
  timespan?: string;
  workspaceId?: string;
}

function runUnifiedHuntingQuery(params: UnifiedHuntingQueryParams) {
  const body: Record<string, string> = { Query: params.query };

  if (params.timespan) {
    body.Timespan = params.timespan;
  }

  if (params.workspaceId) {
    body.workspaceId = params.workspaceId;
  }

  return defenderApiRequest("/runHuntingQuery", {
    method: "POST",
    body,
    useGraph: true,
  });
}

// Backward-compatible tool name; Microsoft Graph now serves the unified hunting schema.
export async function runAdvancedQuery(params: z.infer<typeof RunAdvancedQuerySchema>) {
  return runUnifiedHuntingQuery(params);
}

// Unified Defender XDR and Microsoft Sentinel advanced hunting through Microsoft Graph.
export async function runXdrHuntingQuery(params: z.infer<typeof RunXdrHuntingQuerySchema>) {
  return runUnifiedHuntingQuery(params);
}

export async function getHuntingSchema(params: z.infer<typeof GetHuntingSchemaSchema>) {
  return defenderApiRequest("/runHuntingQuery", {
    method: "POST",
    body: { Query: `${params.tableName} | getschema` },
    useGraph: true,
  });
}

// Tool definitions for MCP
export const advancedHuntingTools = [
  {
    name: "defender_run_advanced_query",
    description: `Run an advanced hunting query using Kusto Query Language (KQL) against the unified Microsoft Defender XDR and Microsoft Sentinel schema through Microsoft Graph Security. This backward-compatible tool now uses the same Graph hunting API as defender_run_xdr_hunting_query.

Available tables include:
- DeviceInfo: Device information and properties
- DeviceNetworkInfo: Network configuration
- DeviceProcessEvents: Process creation and related events
- DeviceNetworkEvents: Network connections and related events
- DeviceFileEvents: File creation, modification, and other events
- DeviceRegistryEvents: Registry operations
- DeviceLogonEvents: Logon and authentication events
- DeviceImageLoadEvents: DLL loading events
- DeviceEvents: Miscellaneous events
- AlertInfo: Alert information
- AlertEvidence: Evidence associated with alerts

Example queries:
- "DeviceProcessEvents | where Timestamp > ago(1h) | limit 100"
- "AlertInfo | where Severity == 'High' | project AlertId, Title, Timestamp"
- "DeviceNetworkEvents | where RemotePort == 443 | summarize count() by DeviceName"

Microsoft Sentinel-native tables such as SigninLogs, AADNonInteractiveUserSignInLogs, CommonSecurityLog, SecurityAlert, and AzureActivity are supported when exposed to the connected Defender portal workspace.

Use the optional timespan argument to request a longer window such as P90D. A shorter time filter in KQL still limits the query. Max 100,000 rows returned.`,
    inputSchema: RunAdvancedQuerySchema,
    handler: runAdvancedQuery,
  },
  {
    name: "defender_run_xdr_hunting_query",
    description: `Run an advanced hunting query using Kusto Query Language (KQL) through Microsoft Graph Security. This queries the unified Microsoft Defender XDR and Microsoft Sentinel advanced hunting schema available in the Microsoft Defender portal.

Available tables include:
- DeviceInfo, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents (Endpoint/MDE)
- AlertInfo: Alert metadata across all Defender workloads
- AlertEvidence: Evidence entities associated with alerts
- IdentityInfo: User identity details from Microsoft Entra ID
- IdentityLogonEvents: Authentication events from identity sources
- IdentityDirectoryEvents: Active Directory object changes
- IdentityQueryEvents: LDAP queries and other identity queries
- EmailEvents: Email messages and delivery actions (Defender for Office 365)
- EmailAttachmentInfo: Email attachment metadata
- EmailUrlInfo: URLs in emails
- EmailPostDeliveryEvents: Actions taken on emails after delivery
- CloudAppEvents: Activity in cloud applications (Defender for Cloud Apps)
- SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs (Microsoft Sentinel/Entra)
- CommonSecurityLog, SecurityAlert, AzureActivity, OfficeActivity, and other Sentinel tables connected to the primary or specified workspace

Example queries:
- "AlertInfo | where Timestamp > ago(7d) | where Title contains 'ransomware'"
- "IdentityLogonEvents | where Timestamp > ago(1d) | where ActionType == 'LogonFailed' | summarize count() by AccountName"
- "AlertEvidence | where AlertId == '<alertId>' | project EntityType, EvidenceRole, FileName, RemoteIP"

Use the optional timespan argument to request a longer window such as P90D. Use workspaceId to target a specific Sentinel Log Analytics workspace. Some tenants do not support joins between Defender-native and Sentinel-native tables in one query. Max 100,000 rows returned.`,
    inputSchema: RunXdrHuntingQuerySchema,
    handler: runXdrHuntingQuery,
  },
  {
    name: "defender_get_hunting_schema",
    description: `Get column names and types for one Microsoft Defender XDR or Microsoft Sentinel advanced hunting table through Microsoft Graph Security.`,
    inputSchema: GetHuntingSchemaSchema,
    handler: getHuntingSchema,
  },
];
