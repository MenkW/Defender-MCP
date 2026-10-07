# Defender-MCP

A **Model Context Protocol (MCP) server** for Microsoft Defender XDR and Microsoft Defender for Endpoint. Enables AI assistants (Claude, Kilo, etc.) to interact with your security environment using natural language — investigating incidents, hunting threats, managing devices, and querying vulnerabilities.

## Features

- **~45 tools** across 9 security categories
- **Multi-resource authentication** — separate Azure AD tokens for Microsoft Graph, the MTP API (`api.security.microsoft.com`), and the WDATP API (`api.securitycenter.microsoft.com`)
- **Unified advanced hunting** — query Defender XDR and Microsoft Sentinel-native tables through Microsoft Graph
- **Incident management** — list, get, update incidents with full alert and evidence detail
- **Device response actions** — isolate machines, run AV scans, collect investigation packages, execute live response
- **Threat intelligence** — create, import, and manage IOC indicators (file hashes, IPs, domains, URLs)
- **Vulnerability management** — CVE lookup, software inventory, security recommendations, remediation tracking

## Tool Categories

| Category | Tools | Description |
|---|---|---|
| Incidents | 4 | List, get, get alerts, update incidents |
| Alerts | 5 | List, get, update, batch-update, create alerts |
| Machines | 16 | Get devices, isolate, AV scan, restrict code execution, live response |
| Advanced Hunting | 3 | Unified Graph KQL queries plus per-table schema discovery |
| Entities | 11 | File hashes, domains, IPs, user alerts and machines |
| Indicators (IoC) | 5 | Get, create, import, delete threat indicators |
| Machine Actions | 12 | Investigation packages, live response, automated investigations |
| Scoring | 5 | Exposure score, secure score, AV health, device health |
| Vulnerabilities | 17 | CVEs, software inventory, recommendations, remediation activities |

## Prerequisites

- **Node.js** 18.0.0 or higher
- **Azure AD App Registration** (Microsoft Entra ID) with the following API permissions granted as **Application** permissions (not delegated):

### Required API Permissions

**Microsoft Graph:**
- `ThreatHunting.Read.All`

**`api.security.microsoft.com` (Microsoft Threat Protection):**
- `AdvancedHunting.Read.All`
- `Incident.Read.All`
- `Incident.ReadWrite.All`

**`WindowsDefenderATP` (Microsoft Defender for Endpoint):**
- `Alert.Read.All`
- `Alert.ReadWrite.All`
- `Machine.Read.All`
- `Machine.ReadWrite.All`
- `Machine.Isolate`
- `Machine.LiveResponse`
- `Machine.Scan`
- `Ti.Read.All`
- `Ti.ReadWrite.All`
- `Vulnerability.Read.All`
- `Software.Read.All`
- `Score.Read.All`
- `SecurityRecommendation.Read.All`

> **Important:** All permissions must be **Application** type and require admin consent.

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MenkW/Defender-MCP.git
   cd Defender-MCP
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure credentials:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and fill in your Azure AD app registration details:
   ```env
   DEFENDER_TENANT_ID=your-tenant-id
   DEFENDER_CLIENT_ID=your-client-id
   DEFENDER_CLIENT_SECRET=your-client-secret
   # Optional overrides; these defaults are used when omitted
   DEFENDER_GRAPH_SCOPE=https://graph.microsoft.com/.default
   DEFENDER_GRAPH_SECURITY_BASE_URL=https://graph.microsoft.com/v1.0/security
   ```

4. **Build:**
   ```bash
   npm run build
   ```

## MCP Configuration

Add to your MCP client config (e.g., Kilo `kilo.json` or Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "defender": {
      "command": "node",
      "args": ["C:/path/to/Defender-MCP/dist/index.js"],
      "env": {
        "DEFENDER_TENANT_ID": "your-tenant-id",
        "DEFENDER_CLIENT_ID": "your-client-id",
        "DEFENDER_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

Or if you use a `.env` file and have it populated:

```json
{
  "mcpServers": {
    "defender": {
      "command": "node",
      "args": ["C:/path/to/Defender-MCP/dist/index.js"]
    }
  }
}
```

## Architecture

```
src/
  index.ts              # MCP server entrypoint -- loads all tool modules
  auth.ts               # Dual-token MSAL authentication (MTP + WDATP scopes)
  api-client.ts         # HTTP client -- routes requests to correct API + token
  tools/
    incidents.ts        # Incident management tools
    alerts.ts           # Alert tools
    machines.ts         # Device/machine tools including response actions
    advanced-hunting.ts # KQL hunting (WDATP and XDR)
    entities.ts         # File, IP, domain, user enrichment
    indicators.ts       # Threat intelligence / IoC management
    machine-actions.ts  # Investigation packages, live response, investigations
    scoring.ts          # Exposure score, secure score, AV health
    vulnerabilities.ts  # CVE, software, recommendations, remediation
```

### Authentication Architecture

The server uses separate Azure AD token acquisition flows for each API resource:

- **Microsoft Graph token** -- scope `https://graph.microsoft.com/.default` -- used for unified Defender XDR and Microsoft Sentinel advanced hunting
- **MTP token** -- scope `https://api.security.microsoft.com/.default` -- used for Incidents
- **WDATP token** -- scope `https://api.securitycenter.microsoft.com/.default` -- used for Alerts, Machines, Indicators, Vulnerabilities, etc.

Both tokens are cached per-scope and automatically refreshed by MSAL.

## Development

```bash
# Run directly with tsx (no build required)
npm run dev

# Build TypeScript to dist/
npm run build

# Run built output
npm start
```

## License

MIT -- see [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
