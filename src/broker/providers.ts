/**
 * Per-provider OAuth configuration for the Grant middleware.
 * Each entry maps a provider key to its Grant config and env var names.
 */

export interface ProviderConfig {
  /** Grant's provider key (e.g. "github", "google") */
  grantKey: string;
  /** Environment variable holding the client_id */
  clientIdEnv: string;
  /**
   * Environment variable holding the client_secret.
   * null = PKCE-only provider (no secret needed)
   */
  secretEnv: string | null;
  /** Whether to enable PKCE for this provider */
  pkce: boolean;
  /** Default OAuth scopes (task.ts can override via ?scope=) */
  scopes: string[];
}

export const PROVIDER_CONFIGS: ReadonlyMap<string, ProviderConfig> = new Map([
  [
    "github",
    {
      grantKey: "github",
      clientIdEnv: "GITHUB_CLIENT_ID",
      secretEnv: "GITHUB_CLIENT_SECRET",
      pkce: true,
      scopes: ["user", "repo"],
    },
  ],
  [
    "slack",
    {
      grantKey: "slack",
      clientIdEnv: "SLACK_CLIENT_ID",
      secretEnv: null,
      pkce: true,
      scopes: ["channels:read"],
    },
  ],
  [
    "google",
    {
      grantKey: "google",
      clientIdEnv: "GOOGLE_CLIENT_ID",
      secretEnv: "GOOGLE_CLIENT_SECRET",
      pkce: true,
      scopes: ["https://www.googleapis.com/auth/userinfo.email"],
    },
  ],
  [
    "spotify",
    {
      grantKey: "spotify",
      clientIdEnv: "SPOTIFY_CLIENT_ID",
      secretEnv: null,
      pkce: true,
      scopes: ["user-read-private", "user-read-email"],
    },
  ],
  [
    "linear",
    {
      grantKey: "linear",
      clientIdEnv: "LINEAR_CLIENT_ID",
      secretEnv: null,
      pkce: true,
      scopes: ["read"],
    },
  ],
  [
    "discord",
    {
      grantKey: "discord",
      clientIdEnv: "DISCORD_CLIENT_ID",
      secretEnv: null,
      pkce: true,
      scopes: ["identify", "email"],
    },
  ],
  [
    "gitlab",
    {
      grantKey: "gitlab",
      clientIdEnv: "GITLAB_CLIENT_ID",
      secretEnv: "GITLAB_CLIENT_SECRET",
      pkce: true,
      scopes: ["read_user", "read_api"],
    },
  ],
  [
    "airtable",
    {
      grantKey: "airtable",
      clientIdEnv: "AIRTABLE_CLIENT_ID",
      secretEnv: "AIRTABLE_CLIENT_SECRET",
      pkce: true,
      scopes: ["data.records:read"],
    },
  ],
  [
    "notion",
    {
      grantKey: "notion",
      clientIdEnv: "NOTION_CLIENT_ID",
      secretEnv: "NOTION_CLIENT_SECRET",
      // Notion does not support PKCE; uses HTTP Basic auth with client_secret
      pkce: false,
      scopes: [],
    },
  ],
  [
    "confluence",
    {
      grantKey: "confluence",
      clientIdEnv: "CONFLUENCE_CLIENT_ID",
      secretEnv: null,
      pkce: true,
      scopes: ["read:me", "read:confluence-content.all", "offline_access"],
    },
  ],
  [
    "salesforce",
    {
      grantKey: "salesforce",
      clientIdEnv: "SALESFORCE_CLIENT_ID",
      secretEnv: null,
      pkce: true,
      scopes: ["api", "refresh_token"],
    },
  ],
  [
    "stripe",
    {
      grantKey: "stripe",
      clientIdEnv: "STRIPE_CLIENT_ID",
      secretEnv: "STRIPE_CLIENT_SECRET",
      // Stripe uses client_secret, not PKCE
      pkce: false,
      scopes: ["read_write"],
    },
  ],
  [
    "office365",
    {
      grantKey: "office365",
      clientIdEnv: "OFFICE365_CLIENT_ID",
      secretEnv: "OFFICE365_CLIENT_SECRET",
      pkce: true,
      scopes: ["offline_access", "User.Read", "Mail.Read"],
    },
  ],
  [
    "azure",
    {
      grantKey: "azure",
      clientIdEnv: "AZURE_CLIENT_ID",
      secretEnv: "AZURE_CLIENT_SECRET",
      pkce: true,
      scopes: ["openid", "profile", "email", "offline_access"],
    },
  ],
]);
