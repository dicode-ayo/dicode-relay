import type { KvAdapter } from "./kv-adapter.js";

const KV_KEY = "tofu.broker_pubkey";

export type TofuResult = "new" | "match" | "mismatch";

export class TofuStore {
  constructor(private kv: KvAdapter) {}

  async checkAndPin(brokerPubkeyB64: string): Promise<TofuResult> {
    const stored = await this.kv.get<string>(KV_KEY);
    if (stored === null) {
      await this.kv.set(KV_KEY, brokerPubkeyB64);
      return "new";
    }
    return stored === brokerPubkeyB64 ? "match" : "mismatch";
  }

  async clear(): Promise<void> {
    await this.kv.delete(KV_KEY);
  }
}
