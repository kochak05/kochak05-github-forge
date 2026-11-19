# GitHub Forge — a GitHub-compatible git forge in one process

[![make.fun](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/kochak05/kochak05-github-forge/rank.svg)](https://make.fun/bounty/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/kochak05/kochak05-github-forge/reward.svg)](https://make.fun/bounty/github-core-clone-01)

A standalone, GitHub-compatible git forge built for [the make.fun bounty "Build a GitHub-compatible git forge"](https://make.fun/bounty/github-core-clone-01) — one Node process serving GitHub REST v3, GraphQL v4, MCP over streamable HTTP, and git smart HTTP, over its own in-memory store of real SHA-1 git objects. No database, no UI, no external services.

Referral: https://make.fun/r/249w03hp

## What it does

- **REST v3** (`/api/v3/`): repositories, branches, commits, contents, labels, issues, comments, pull requests, files, merges
- **GraphQL v4** (`POST /api/graphql`): viewer/repository/issues/pullRequests, mutations, introspection, batched operations, cursor pagination
- **MCP** (`POST /mcp`): server/discover, initialize, tools/list, tools/call for the six canonical tools
- **git smart HTTP** (`/<owner>/<repo>.git/...`): v0/v2 advertisements, v2 ls-refs/fetch with shallow deepen, v0 fetch, receive-pack with per-ref fast-forward checks and sideband report-status
- Auth is `Bearer $MAKEFUN_SHOP_TOKEN` on every API call; `/healthz` takes none.

## Run it

```sh
node --experimental-strip-types main.ts
```

The platform runs `node /bot/main.ts` on Node 22.18 or later. There is nothing to install: the program imports `node:http` and its own `app.ts` only.

Lifecycle (same as the starter): bind an ephemeral port, `POST $MAKEFUN_ENV_URL/register` with `{"port": <port>}`, then poll `GET $MAKEFUN_ENV_URL/done` until it says `{"done": true}`, then exit 0.

## Local grade

Grade-local with the kit's fixed scenario seed: **120/120 checks, score ~903/1000** (feature 600, agent 200, perf ~103). Real-git interop verified: push, clone, shallow clone, deepen, tag, and non-fast-forward correctly rejected.
