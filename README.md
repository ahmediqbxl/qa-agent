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
/qa-agent:qa ux             # usability: task walkthroughs + accessibility/layout/visual checks
/qa-agent:qa-profile        # write or repair qa/profile.yaml for a new app
```

## UX testing

`/qa-agent:qa ux` answers the questions a reviewer asks about a flow: *did
everything work, did the UI break along the way, did any error pop up, and did
the on-screen guidance make sense?*

- **Task walkthroughs** (`ux.tasks`): the agent gets only a goal and a persona
  ("add a client, set up your firm's export template, sort their statement,
  export it"), finds its own way, and logs every step, wrong turn and confusing
  piece of copy with `qa.py ux-log`. The report shows steps against budget,
  plus a "where the guidance fell short" list that quotes the exact copy.
- **Automated checks** (`qa.py ux-check`): for every screen, viewport and theme,
  it records time-to-ready, axe-core accessibility violations, cut-off and
  overlapping controls, small tap targets, console and API errors, and a
  screenshot diffed against the baseline (`qa.py ux-baseline` accepts changes).
  `--changed` checks only the screens your branch touches.

## Install

Requirements: Claude Code, [uv](https://docs.astral.sh/uv/), Node 18+ (for
Playwright MCP), and whatever the app's own stack needs (Docker, Postgres...).

```
/plugin marketplace add ahmediqbxl/qa-agent
/plugin install qa-agent@qa-agent
```

### Add it to a repo (one command)

From the repo root:

```bash
# a new app: writes qa/profile.yaml from the template, wires .claude/settings.json, ignores .qa/
~/.claude/plugins/cache/qa-agent/qa-agent/*/scripts/qa.py init

# a repo next to one that already has a profile (e.g. a frontend beside its backend):
~/.claude/plugins/cache/qa-agent/qa-agent/*/scripts/qa.py init --extends ../../backend/qa/profile.yaml
```

Or just ask Claude: `/qa-agent:qa-profile`. With `extends`, the new profile
reuses the other repo's services, personas, journeys and UX screens, and only
overrides what differs.

`init` adds this to `.claude/settings.json`:

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
| `scripts/ux.py` | The UX checker that `qa.py ux-check` runs (Playwright, axe-core, Pillow), in its own environment. |
| `templates/profile.example.yaml` | The profile schema, commented. |

Run artifacts (logs, HTTP/SQL evidence, UX screenshots, `report.md`,
`report.json`) are written to `<app>/.qa/runs/<timestamp>/`. That directory is
git-ignored automatically. Browser downloads land in `.qa/browser/` under the
Claude Code project directory.

Running as root (Docker, CI, cloud sessions)? The browser launches with
`--no-sandbox` automatically. Set `QA_CHROMIUM=/path/to/chrome` to use an
installed Chromium; otherwise run `npx playwright install chromium` once.

## Safety

- The runner refuses every HTTP request and DB connection to a host outside
  `allowed_hosts`, and the hook does the same for the browser.
- `qa.py sql` runs only single statements, in a read-only session.
- Reset steps belong in the profile and must be local-only.
