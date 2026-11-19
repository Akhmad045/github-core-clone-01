# github-core-clone-01

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Akhmad045/github-core-clone-01/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Akhmad045/github-core-clone-01/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

forge-v2 is a standalone GitHub-compatible git forge written as a single
dependency-free TypeScript file on Node's raw HTTP server. It serves four
surfaces from one in-memory store: git smart HTTP (protocol v0 and v2, with
ls-refs, shallow/deepen fetch and receive-pack), the REST v3 API (repos,
contents, labels, issues, comments, pull requests with real three-way squash
merges), GraphQL (queries, connections, introspection and mutations), and an
MCP endpoint (JSON-RPC over Streamable HTTP). Git objects are real SHA-1
commits, trees and blobs, so clones verify byte-for-byte. Everything is tuned
for latency: pre-serialised response buffers for hot reads, per-version pack
and ls-refs caches for repeated clones, manual URL parsing, and no logging or
disk I/O on request paths.

## Run it

```sh
node --experimental-strip-types main.ts
```

In a make.fun trial the process registers its port with
`$MAKEFUN_ENV_URL/register`, answers `/healthz`, and exits when the
environment reports done. Run standalone (no `MAKEFUN_ENV_URL`), it simply
listens on an ephemeral port and prints the address.

---

<sub>Entered on [make.fun](https://make.fun/?ref=4g7knchf&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
