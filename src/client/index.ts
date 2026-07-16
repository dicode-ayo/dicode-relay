export { RelayClient } from "./client.js";
export type {
  RelayClientOptions,
  RelayClientLogger,
  RelayClientTls,
  RelayStatus,
} from "./client.js";

export { Identity } from "./identity.js";
export type { StoredIdentity } from "./identity.js";

export { buildAuthURL, decryptTokenEnvelope } from "./auth.js";
export type { BuildAuthURLOpts, BuildAuthURLResult } from "./auth.js";

export type { HandshakeResult } from "./handshake.js";

export { generateSelfSignedServerCert } from "../shared/certs.js";
export type { GeneratedCert, GenerateServerCertOpts } from "../shared/certs.js";
