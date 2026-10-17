# qa-agent

A QA agent for Claude Code that works on any app. The core is shared. Each app
supplies one file, `qa/profile.yaml`, that says how to boot it, who its users
are, and which rules must never break.

The agent boots the app locally, signs in as each persona, walks the
journeys in a real browser and through the API, tries to break the
invariants (tenant isolation, role gates, money integrity), and writes a
report. Every finding comes with steps to reproduce and evidence.

```
/qa-agent:qa changed        # items affected by this branch's diff (plus always-on invariants)
/qa-agent:qa full           # every journey and invariant
/qa-agent:qa explore        # + exploratory charters
/qa-agent:qa only=inv-tenant-isolation
/qa-agent:qa-profile        # write or repair qa/profile.yaml for a new app
```

## Install

Requirements: Claude Code, [uv](https://docs.astral.sh/uv/), Node 18+ (for
Playwright MCP), and whatever the app's own stack needs (Docker, Postgres...).

```
/plugin marketplace add ahmediqbxl/qa-agent
/plugin install qa-agent@qa-agent
```

An app repo can pre-wire this for everyone who clones it, in
`.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "qa-agent": { "source": { "source": "github", "repo": "ahmediqbxl/qa-agent" } }
  },
  "enabledPlugins": { "qa-agent@qa-agent": true }
}
```

## How it fits together

| Piece | What it does |
|---|---|
| `skills/qa` | The agent's procedure: plan, then invariants first, then journeys and charters, then report. |
| `scripts/qa.py` | Deterministic runner: `start`, `up`, `reset`, `login`, `http`, `sql` (read-only), `plan`, `cover`, `finding`, `report`, `stop`. |
| `.mcp.json` + `scripts/playwright-mcp.sh` | Headless browser through Playwright MCP (`QA_HEADED=1` shows it, `QA_CHROMIUM=` picks a binary). |
| `hooks/hooks.json` | Blocks browser navigation to any host not in the profile's `allowed_hosts`. |
| `templates/profile.example.yaml` | The profile schema, commented. |

Run artifacts (logs, HTTP/SQL evidence, `report.md`, `report.json`) are written
to `<app>/.qa/runs/<timestamp>/`. That directory is git-ignored automatically.

## Safety

- The runner refuses every HTTP request and DB connection to a host outside
  `allowed_hosts`, and the hook does the same for the browser.
- `qa.py sql` runs only single statements, in a read-only session.
- Reset steps belong in the profile and must be local-only.
