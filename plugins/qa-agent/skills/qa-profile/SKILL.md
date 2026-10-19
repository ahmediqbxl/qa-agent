---
name: qa-profile
description: Write or update qa/profile.yaml so the QA agent (/qa-agent:qa) can test this app. Use when onboarding a new app to the QA agent, or when a profile is stale (boot fails, journeys reference screens or endpoints that no longer exist).
---

# Author a QA profile

**Start with `qa.py init`.** It writes `qa/profile.yaml` from the template,
registers the plugin in `.claude/settings.json` (so teammates get it offered)
and git-ignores `.qa/`. **If another repo already has a profile for the same
app** (a frontend next to its backend), reuse it rather than writing a new one:

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/qa.py" init --extends ../../<backend-repo>/qa/profile.yaml --diff-base origin/main
```

`extends` layers this repo's file over the base. Maps merge, lists replace,
and relative paths keep resolving against the base repo, so only override what
differs (usually `diff_base` and a few `ux.screens`).

The QA agent stays the same for every app. What changes from app to app is
`qa/profile.yaml`. The schema, with comments on every key, is in
`${CLAUDE_PLUGIN_ROOT}/templates/profile.example.yaml`. Read it first.

## Gather the facts from the repo, don't invent them

1. **Boot**: README, CLAUDE.md/AGENTS.md, docker-compose files, package.json
   scripts, Makefiles. Get the exact commands, ports and health endpoints.
   Put each service in order and give it a `ready` check.
2. **Reset and seed**: dev-only reset endpoints, seed scripts, `db reset`.
   Resetting has to be **local-only**. If the only reset path touches a
   shared environment, stop and ask.
3. **Personas**: every role the app has, plus a **second tenant** for each
   role that owns data. You cannot test isolation without a second tenant. Use
   dev-login endpoints or seeded accounts with known passwords. Find where the
   frontend keeps its session (sessionStorage/localStorage keys) so
   `personas.*.browser` can sign the browser in.
4. **Hosts**: `allowed_hosts` lists only local or staging hosts. Look for env
   files that point at production (`.env` vs `.env.local`), and pin the safe
   one in `env`/`services`.
5. **Determinism**: stub or dummy providers (OCR, LLM, payments, email), flags
   that turn them on, and fixture files a journey can upload.
6. **Journeys**: the app's documented golden path(s), written as user-level
   steps plus objective `checks`. Map each one to the source `paths` that
   would break it.
7. **Invariants**: the rules that cost the most when broken. Look for:
   ownership/tenant checks, role gates, RLS policies, "never shown before X"
   rules, and money/tax totals that must reconcile. Write `how` as concrete
   attacks.
8. **Charters**: two or three exploratory missions around the riskiest or
   newest features.
9. **UX** (`ux:`): `screens` (path, persona, `ready` marker, `via` for screens
   that only restore from in-app state, and the source `paths` that change
   them), `viewports` (include one touch phone), `themes` (how the app stores
   its theme, e.g. a localStorage key), `design_docs`, and 3-5 `tasks`. A task
   is a **goal** in the user's words plus an objective `success` check, never
   steps. Include the flows the team actually asks about ("can an accountant
   add a client and export with their own template?").

## Validate

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/qa.py" validate
```

Then do a dry run: `start`, `up`, `reset`, `login`, `plan`, `stop`. Fix
anything that fails before handing the profile over.
