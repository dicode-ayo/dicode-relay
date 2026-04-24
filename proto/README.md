# proto/

Vendored copy of the relay protocol schema from
[`dicode-ayo/dicode-core:proto/relay.proto`](https://github.com/dicode-ayo/dicode-core/blob/main/proto/relay.proto).
This file MUST stay byte-identical with upstream — a future CI check should
enforce that (see TODO below).

Initial import: dicode-core commit `b0ebaf6` (the branch that became
[dicode-core PR #199](https://github.com/dicode-ayo/dicode-core/pull/199)).

## Resync when upstream changes

```sh
curl -fsSL \
  https://raw.githubusercontent.com/dicode-ayo/dicode-core/main/proto/relay.proto \
  > proto/relay.proto
npm run proto   # regenerates src/relay/pb/relay_pb.ts
npm test        # verify wire compatibility
```

Then update the commit reference above to the new upstream SHA.

## Why vendored, not a git submodule

A submodule would be precise but drags the entire dicode-core repo into
`git clone`. A one-file `curl` is cheap and keeps the dependency graph flat.
The tradeoff is that drift is not automatic — hence the CI TODO.

## TODO

- Add a CI job that diffs `proto/relay.proto` against the upstream `main`
  branch and fails if out of sync without an explicit opt-out label. Until
  this exists, drift only surfaces as handshake-fail symptoms in production.
