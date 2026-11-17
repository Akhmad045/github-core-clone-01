# forge

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5.x-blue.svg)](https://www.typescriptlang.org/)

A standalone, single-process GitHub-compatible git forge written in TypeScript
with **no dependencies** — Node.js standard library only. It implements, from
scratch, the git object store (SHA-1 objects, packfiles, pkt-line framing,
delta decoding), git smart HTTP (upload-pack v2 + v0, receive-pack v0 with
fast-forward-only pushes), the GitHub REST v3 API, the GraphQL v4 API, and the
MCP Streamable HTTP endpoint (protocol revision 2026-07-28), all on top of one
deterministic in-memory store.

## About

`forge` was built as a conformance entry for the `github-core-clone-01`
competition. Every response is deterministic: commit timestamps derive from
`MAKEFUN_TRIAL_NOW` plus a monotonic counter, ids come from counters, and no
wall clock or unseeded randomness is used anywhere, so a trial and its replay
produce byte-identical state exports.

## Run

```bash
npm run build
MAKEFUN_ENV_URL=http://127.0.0.1:PORT MAKEFUN_SHOP_TOKEN=token node dist/main.js
```

The server binds an ephemeral port, registers it with the harness at
`$MAKEFUN_ENV_URL/register`, then serves until `$MAKEFUN_ENV_URL/done`
reports completion.

## Features

- **Git**: upload-pack v2 (`ls-refs`, `fetch` with shallow/deepen) and v0,
  receive-pack v0 (`report-status`, `side-band-64k`, `delete-refs`),
  fast-forward-only pushes with per-ref `ok`/`ng` lines, annotated tags,
  from-scratch packfile reader/writer (OFS_DELTA and REF_DELTA decoding).
- **REST v3**: repositories, branches, refs, commits, contents (create/update/
  delete with stale-sha 409), labels, issues, comments, pull requests, squash
  merge with three-way conflict detection, `Link` pagination, JSON errors,
  `X-GitHub-Request-Id` on every reply.
- **GraphQL v4**: `viewer`, `repository`, `node`, issues and pull requests with
  cursor pagination, `__type` introspection, create/close issue, create/merge
  pull request, add comment, opaque global ids, unknown fields reported as
  GraphQL errors with HTTP 200.
- **MCP**: `server/discover`, `initialize`, `tools/list` (byte-identical every
  call), `tools/call` for `create_repo`, `get_repo`, `create_issue`,
  `list_issues`, `create_pull_request`, `merge_pull_request`.
- **Auth**: every endpoint requires `Authorization: Bearer <token>` matching
  `MAKEFUN_SHOP_TOKEN` (any non-empty token when the variable is unset);
  wrong-owner resources answer 404, never 403.

## License

MIT — see [LICENSE](LICENSE).
