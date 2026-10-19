#!/usr/bin/env bash
# Launches Playwright MCP for the QA agent.
#   QA_HEADED=1        show the browser window (default: headless)
#   QA_CHROMIUM=/path  use a pre-installed Chromium instead of Playwright's own
#   QA_VIEWPORT=WxH    viewport size (default 1440x900)
#   QA_NO_SANDBOX=1    disable Chromium's sandbox (automatic when running as root)
set -euo pipefail
args=(--isolated --viewport-size "${QA_VIEWPORT:-1440x900}" --console-level warning)
[[ "${QA_HEADED:-0}" == "1" ]] || args+=(--headless)
# Chromium refuses to start sandboxed as root (containers, CI runners).
[[ "$(id -u)" == "0" || "${QA_NO_SANDBOX:-0}" == "1" ]] && args+=(--no-sandbox)
chromium="${QA_CHROMIUM:-}"
if [[ -z "$chromium" && -x /opt/pw-browsers/chromium ]]; then
  chromium=/opt/pw-browsers/chromium   # Claude Code cloud containers
fi
[[ -n "$chromium" ]] && args+=(--executable-path "$chromium")
out_dir="${CLAUDE_PROJECT_DIR:-$PWD}/.qa/browser"
mkdir -p "$out_dir"
args+=(--output-dir "$out_dir")
exec npx -y @playwright/mcp@0.0.83 "${args[@]}"
