import { ConfidentialClientApplication, Configuration } from "@azure/msal-node";

export interface DefenderAuthConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

// Separate resource scopes for each Defender API surface
const MTP_SCOPE   = "https://api.security.microsoft.com/.default";   // Incidents
const WDATP_SCOPE = "https://api.securitycenter.microsoft.com/.default"; // Alerts, Machines, Files, IPs, etc.
const GRAPH_SCOPE = process.env.DEFENDER_GRAPH_SCOPE ?? "https://graph.microsoft.com/.default";

let msalClient: ConfidentialClientApplication | null = null;

// Separate token caches per scope
const tokenCache: Record<string, { token: string; expiresAt: number }> = {};

export function initializeAuth(config: DefenderAuthConfig): void {
  const msalConfig: Configuration = {
    auth: {
      clientId: config.clientId,
      authority: `https://login.microsoftonline.com/${config.tenantId}`,
      clientSecret: config.clientSecret,
    },
  };

  msalClient = new ConfidentialClientApplication(msalConfig);
}

async function getTokenForScope(scope: string): Promise<string> {
  if (!msalClient) {
    throw new Error(
      "Authentication not initialized. Please set DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID, and DEFENDER_CLIENT_SECRET environment variables."
    );
  }

  // Return cached token if still valid (with 60s buffer)
  const cached = tokenCache[scope];
  if (cached && Date.now() < cached.expiresAt - 60000) {
    return cached.token;
  }

  const result = await msalClient.acquireTokenByClientCredential({
    scopes: [scope],
  });

  if (!result || !result.accessToken) {
    throw new Error(`Failed to acquire access token for scope: ${scope}`);
  }

  tokenCache[scope] = {
    token: result.accessToken,
    expiresAt: result.expiresOn ? result.expiresOn.getTime() : Date.now() + 3600000,
  };

  return tokenCache[scope].token;
}

/** Token for Incidents and XDR Advanced Hunting (Microsoft Threat Protection) */
export async function getAccessToken(): Promise<string> {
  return getTokenForScope(MTP_SCOPE);
}

/** Token for Alerts, Machines, Files, IPs, URLs, Users, WDATP Advanced Queries */
export async function getWdatpAccessToken(): Promise<string> {
  return getTokenForScope(WDATP_SCOPE);
}

/** Token for Microsoft Graph Security API Advanced Hunting */
export async function getGraphAccessToken(): Promise<string> {
  return getTokenForScope(GRAPH_SCOPE);
}

export function isAuthConfigured(): boolean {
  return msalClient !== null;
}
