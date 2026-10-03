# The addon manifest, version 1

The contract between a Nexora addon and the panel, the directory at
`addons.nexora-panel.org` and the panel's install wizard. The code that
enforces it is the `manifest` package of this module — the panel validates
with the same code — so when this file and the code disagree, the code is
right and this file is the bug. `api: 1` may still change until the first
release of Nexora Shop, when it is frozen.

## Where it lives

- **`nexora-addon.json` at the root of the addon's public repository** — what
  the directory and the install wizard read before anything runs. For a
  closed addon that is its public distribution repository.
- **The same file served by the running addon** at
  `/.well-known/nexora-addon.json`, which registration reads.
- **Signed**: an official addon by Nexora, a verified one with its
  developer's own key (`nexora-addon keygen` / `sign`), which the
  directory's signed index vouches for. The signature covers every field but
  `signature`, re-encoded with keys sorted, so the file may be indented or
  reordered freely. An unsigned addon is registered by hand.

## Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `api` | yes | `1` (this document) or `0` (Phase F's; may not carry any field below marked v1) |
| `slug` | yes | the addon id: `a-z0-9_-`, starting with a letter or digit, at most 32 |
| `name` | yes | at most 64 characters |
| `version` | | the release, semver; the directory compares it for update badges |
| `publisher` | | at most 64 characters |
| `scopes` | one of scopes/webhook | `[{scope, purpose}]`, the API token's permissions, each with the reason shown on the consent screen |
| `events`, `webhook` | together | the events the addon hears and the path they are POSTed to |
| `setup` | yes | the path the credentials are delivered to, with the claim code |
| `health` | | a path answering 200 when healthy; polled every minute |
| `ui` | | the entry point: a path or an absolute http(s) URL |
| `description` | v1 | by language (`en`, `fa`, `ru`, `zh`), English required when given, at most 500 each |
| `license` | v1 | an SPDX id or `proprietary`, at most 64 |
| `paid` | v1 | the addon is sold; its licence is its own, the panel checks nothing |
| `docs` | v1 | an absolute http(s) URL |
| `requires.panel` | v1 | `">=X.Y.Z"`; a panel older than that refuses the addon and says why |
| `install` | v1 | how it is installed, below; an addon without one can only be registered by its address |
| `rateLimit` | v1 | requests a minute the token may make, 1–600; absent is the panel's default, 120. Shown on the consent screen; a newer manifest asking more waits for approval |
| `signature` | | base64 Ed25519 |

## `install`

```json
"install": {
  "docker": { "image": "ghcr.io/nexora-vpn/shop", "compose": "deploy/compose.yml" },
  "binary": { "linux-amd64": "shop-linux-amd64.tar.gz", "linux-arm64": "shop-linux-arm64.tar.gz" },
  "options": [ … ]
}
```

- **`docker.image`** is a registry path **without a tag**: the release's
  version is the tag. **`docker.compose`** is a relative path in the
  repository and the release.
- **`binary`** maps a platform (`linux-amd64`, `linux-arm64`, `linux-armv7`,
  `linux-armv6`, `linux-armv5`, `linux-386`, `linux-s390x`, `linux-riscv64`)
  to a release asset's file name; the addon's install script puts it under
  systemd (`--method script`).
- At least one of the two.

## `install.options`

The questions the install asks, at most 32, in the order shown:

```json
{ "key": "database", "type": "choice", "choices": ["sqlite", "postgres"], "default": "sqlite",
  "label": { "en": "Database", "fa": "پایگاه داده" } },
{ "key": "database_dsn", "type": "secret", "required": true, "when": { "database": "postgres" },
  "label": { "en": "PostgreSQL DSN" } }
```

| Field | Meaning |
| --- | --- |
| `key` | `a-z0-9_`, starting with a letter, at most 32; unique |
| `type` | `string`, `secret`, `number`, `port`, `bool`, `choice`, `url` — the whole list |
| `label` | by language, English required, at most 80 each |
| `help` | by language, at most 300 each |
| `default` | a JSON value of the option's type; never on a `secret` |
| `required` | the install cannot go on without an answer |
| `choices` | a `choice`'s values, 1–32, each at most 64 |
| `when` | `{ "<key>": "<value>" }` — shown only while that option, declared **before** this one and a `choice` or `bool`, has that value (`"true"` / `"false"` for a bool) |

Answers reach the addon as **environment variables `NEXORA_OPT_<KEY>`** (an
`.env` beside the compose file, or the systemd unit's `EnvironmentFile`),
beside **`NEXORA_PANEL_URL`** and **`NEXORA_CLAIM_CODE`**, the code the panel
issued for the install. A `bool` is `true` / `false`, a number in its
JSON spelling.
