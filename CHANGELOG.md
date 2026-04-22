# Changelog

## [0.1.1](https://github.com/dicode-ayo/dicode-relay/compare/v0.1.0...v0.1.1) (2026-04-22)


### Features

* **broker:** accept decrypt_pubkey in hello + announce protocol: 2 ([#28](https://github.com/dicode-ayo/dicode-relay/issues/28)) ([#29](https://github.com/dicode-ayo/dicode-relay/issues/29)) ([d6e2c1d](https://github.com/dicode-ayo/dicode-relay/commit/d6e2c1da2f807037dea0ff9ec0d6cefc9ac10ef1))
* **broker:** E2E mock OAuth provider gated by DICODE_E2E_MOCK_PROVIDER ([#32](https://github.com/dicode-ayo/dicode-relay/issues/32)) ([eaede04](https://github.com/dicode-ayo/dicode-relay/commit/eaede040321cde4a0d5e7738d82fec760be8e924))
* **config:** extract relay configuration to YAML ([#26](https://github.com/dicode-ayo/dicode-relay/issues/26)) ([5a23121](https://github.com/dicode-ayo/dicode-relay/commit/5a23121580c6b97866ee917d36dab7d3bb894932))
* initial commit ([51153ee](https://github.com/dicode-ayo/dicode-relay/commit/51153eebed58044e74795e198fdcb03283bd2c3e))
* **oauth:** bind message type as GCM AAD on delivery envelopes ([#25](https://github.com/dicode-ayo/dicode-relay/issues/25)) ([98eebda](https://github.com/dicode-ayo/dicode-relay/commit/98eebda113e13af97f941ce5260c30368dab891b))
* **relay:** add EventEmitter for client lifecycle events ([0e06ad4](https://github.com/dicode-ayo/dicode-relay/commit/0e06ad4ba3891c50110e256510690f000c262858))
* **status:** add HTTP Basic Auth middleware for status page ([7f11d58](https://github.com/dicode-ayo/dicode-relay/commit/7f11d5865d117ae1ac7f29c199c61a06efe80a09))
* **status:** add MetricsCollector with sliding-window ring buffers ([dccc4e7](https://github.com/dicode-ayo/dicode-relay/commit/dccc4e7534b7f19dd4f9a45b0dd311fc62b9fffc))
* **status:** add server-rendered HTML page and JSON builder ([7bc8d4f](https://github.com/dicode-ayo/dicode-relay/commit/7bc8d4f01b5f5be7bd53cd8b1ec873078ad05c8a))
* **status:** wire metrics, auth, and status routes into server ([c47c483](https://github.com/dicode-ayo/dicode-relay/commit/c47c483f4f102df16f2bf79057358f5740134050))


### Bug Fixes

* fix port ([378b767](https://github.com/dicode-ayo/dicode-relay/commit/378b7676397881eda6a2f7767f99eae14d965d29))
* **relay:** remove unsafe type cast in webhook path param ([8406280](https://github.com/dicode-ayo/dicode-relay/commit/8406280f569a1387830bbe366668d6dbe50f8e58))
* **relay:** resolve ESLint errors in webhook forwarding handler ([c305f9e](https://github.com/dicode-ayo/dicode-relay/commit/c305f9e388a5388894d52d876864a4fde483b0c0))
* **status:** resolve ESLint errors in auth and metrics modules ([6349a93](https://github.com/dicode-ayo/dicode-relay/commit/6349a93f7976e14fe5924d0bc9dc39e06f8fd03e))


### Documentation

* add status page design spec ([9eb24c9](https://github.com/dicode-ayo/dicode-relay/commit/9eb24c9f24341f474f481d17ad54962536584682))
* add status page implementation plan ([85be096](https://github.com/dicode-ayo/dicode-relay/commit/85be096d2777f9c063b205ab115497037e9cd617))


### Refactors

* **relay:** remove HTML rewriting — relay is now a transparent proxy ([d3ae384](https://github.com/dicode-ayo/dicode-relay/commit/d3ae3845c6bfc2b0e85f38e65515dfb8a27ba762))
* transparent relay proxy — remove HTML rewriting ([4f535ac](https://github.com/dicode-ayo/dicode-relay/commit/4f535ac6cbf1c0fafe39bd85bb511710d7855f1e))
