#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["playwright==1.55.0", "axe-playwright-python==0.1.8", "pillow>=10"]
# ///
"""qa-agent UX checks: the objective half of UX testing.

Called by ``qa.py ux-check`` with a JSON job file; not meant to be run by hand.
For every screen x viewport x theme it opens a fresh, signed-in browser
context and records:

- time until the screen's ``ready`` marker is visible
- console errors, uncaught page errors, 4xx/5xx API responses
- axe-core accessibility violations (WCAG tags from the profile)
- layout problems: horizontal page overflow, elements cut off at the
  viewport edge outside any scroll container, tap targets under 24px on
  touch viewports
- a screenshot, diffed against the baseline when one exists

Results go to ``<run>/ux/results.json`` and screenshots to ``<run>/ux/shots``.
Everything the browser requests is checked against ``allowed_hosts``.
"""

from __future__ import annotations

import json
import re
import sys
import time
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

LAYOUT_JS = r"""
({touch}) => {
  const vw = document.documentElement.clientWidth;
  const out = {pageOverflow: document.documentElement.scrollWidth - vw, clipped: [], overlaps: [], smallTargets: []};
  const label = (el) => {
    const t = (el.getAttribute('aria-label') || el.innerText || el.getAttribute('title') || '').trim().replace(/\s+/g, ' ');
    return `${el.tagName.toLowerCase()}${t ? ' "' + t.slice(0, 40) + '"' : ''}`;
  };
  // The box an element is actually visible in: the viewport, narrowed by any
  // ancestor that hides overflow. An ancestor that scrolls is fine (reachable).
  const clipBox = (el) => {
    let box = {left: 0, right: vw};
    for (let p = el.parentElement; p && p !== document.documentElement; p = p.parentElement) {
      const s = getComputedStyle(p);
      if (/(auto|scroll)/.test(s.overflowX)) return null;
      if (/(hidden|clip)/.test(s.overflowX)) {
        const r = p.getBoundingClientRect();
        box = {left: Math.max(box.left, r.left), right: Math.min(box.right, r.right)};
      }
    }
    return box;
  };
  const inScroller = (el) => {
    for (let p = el.parentElement; p && p !== document.documentElement; p = p.parentElement) {
      const s = getComputedStyle(p);
      if (/(auto|scroll)/.test(s.overflowY + s.overflowX) && (p.scrollHeight > p.clientHeight + 1 || p.scrollWidth > p.clientWidth + 1)) return true;
    }
    return false;
  };
  const interactive = 'button, a[href], input:not([type=hidden]), select, textarea, [role=tab], [role=button], [role=menuitem], [role=checkbox], [role=radio]';
  const visible = [];
  for (const el of document.querySelectorAll(interactive + ', h1, h2, h3, label')) {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    if (!r.width || !r.height || s.visibility === 'hidden' || s.opacity === '0' || el.closest('[aria-hidden=true]')) continue;
    if (r.bottom < 0 || r.top > window.innerHeight) continue;
    const box = clipBox(el);
    if (box && (r.right > box.right + 1 || r.left < box.left - 1) && (r.width > 8)) {
      const cut = Math.round(Math.max(r.right - box.right, box.left - r.left));
      if (cut > 2) out.clipped.push({el: label(el), cutPx: cut});
    }
    if (el.matches(interactive)) visible.push([el, r]);
    // Visually hidden inputs (sr-only radios behind styled labels) are not tap targets.
    if (touch && el.matches(interactive) && !el.matches('label') && r.width > 2 && r.height > 2 && (r.width < 24 || r.height < 24)) {
      out.smallTargets.push({el: label(el), w: Math.round(r.width), h: Math.round(r.height)});
    }
  }
  // Interactive elements drawn on top of each other (neither contains the other).
  for (let i = 0; i < visible.length && out.overlaps.length < 15; i++) {
    for (let j = i + 1; j < visible.length; j++) {
      const [a, ra] = visible[i], [b, rb] = visible[j];
      if (a.contains(b) || b.contains(a)) continue;
      // Content scrolled under a pinned bar, or an icon button inside a field
      // (password "Show", search clear), is intended - not a layout bug.
      if (inScroller(a) || inScroller(b)) continue;
      const inside = (x, y) => x.left >= y.left - 1 && x.right <= y.right + 1 && x.top >= y.top - 1 && x.bottom <= y.bottom + 1;
      if ((a.matches('input, textarea') && inside(rb, ra)) || (b.matches('input, textarea') && inside(ra, rb))) continue;
      const w = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
      const h = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
      if (w > 4 && h > 4 && w * h > 0.25 * Math.min(ra.width * ra.height, rb.width * rb.height)) {
        out.overlaps.push({a: label(a), b: label(b), px: Math.round(w * h)});
      }
    }
  }
  out.clipped = out.clipped.slice(0, 15);
  out.smallTargets = out.smallTargets.slice(0, 15);
  return out;
}
"""


def host_allowed(host: str, allowed: list[str]) -> bool:
    host = (host or "").lower().strip("[]")
    for pattern in allowed:
        pattern = pattern.lower()
        if (pattern.startswith("*.") and host.endswith(pattern[1:])) or host == pattern:
            return True
    return False


def storage_script(origin_host: str, session: dict, local: dict) -> str:
    """Init script that seeds web storage before the app's own scripts run."""
    stmts = [
        f"sessionStorage.setItem({json.dumps(k)}, {json.dumps(v)});" for k, v in session.items()
    ]
    stmts += [f"localStorage.setItem({json.dumps(k)}, {json.dumps(v)});" for k, v in local.items()]
    if not stmts:
        return ""
    return f"if (location.host === {json.dumps(origin_host)}) {{ try {{ {' '.join(stmts)} }} catch (e) {{}} }}"


def diff_ratio(a: Path, b: Path) -> float | None:
    from PIL import Image, ImageChops

    try:
        ia, ib = Image.open(a).convert("RGB"), Image.open(b).convert("RGB")
    except OSError:
        return None
    if ia.size != ib.size:
        return 1.0
    diff = ImageChops.difference(ia, ib).convert("L").point(lambda v: 255 if v > 24 else 0)
    hist = diff.histogram()
    changed = sum(hist[1:])
    return changed / (ia.size[0] * ia.size[1])


def run_job(job: dict[str, Any]) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright

    allowed = job["allowed_hosts"]
    run_dir = Path(job["run_dir"])
    shots = run_dir / "ux" / "shots"
    shots.mkdir(parents=True, exist_ok=True)
    baseline = Path(job["baseline_dir"]) if job.get("baseline_dir") else None
    axe_js = (resources.files("axe_playwright_python") / "axe.min.js").read_text()
    axe_tags = job.get("axe", {}).get("tags", ["wcag2a", "wcag2aa"])
    axe_ignore = set(job.get("axe", {}).get("ignore", []))
    impacts = job.get("axe", {}).get("impacts", ["critical", "serious"])
    diff_threshold = float(job.get("diff_threshold", 0.01))
    results: list[dict[str, Any]] = []

    launch: dict[str, Any] = {"headless": True}
    if job.get("chromium"):
        launch["executable_path"] = job["chromium"]
    with sync_playwright() as p:
        browser = p.chromium.launch(**launch)
        for screen in job["screens"]:
            persona = job["personas"].get(screen.get("persona") or "", {})
            for vp_name in screen.get("viewports") or list(job["viewports"]):
                vp = job["viewports"][vp_name]
                for theme_name in screen.get("themes") or list(job["themes"] or {"default": {}}):
                    theme = (job["themes"] or {}).get(theme_name, {})
                    results.append(
                        check_one(
                            browser,
                            job,
                            screen,
                            persona,
                            vp_name,
                            vp,
                            theme_name,
                            theme,
                            allowed,
                            shots,
                            baseline,
                            axe_js,
                            axe_tags,
                            axe_ignore,
                            impacts,
                            diff_threshold,
                        )
                    )
        browser.close()
    return {"results": results}


def check_one(
    browser,
    job,
    screen,
    persona,
    vp_name,
    vp,
    theme_name,
    theme,
    allowed,
    shots,
    baseline,
    axe_js,
    axe_tags,
    axe_ignore,
    impacts,
    diff_threshold,
) -> dict[str, Any]:
    url = job["base_url"].rstrip("/") + "/" + screen["path"].lstrip("/")
    key = f"{screen['id']}--{vp_name}--{theme_name}"
    rec: dict[str, Any] = {
        "screen": screen["id"],
        "viewport": vp_name,
        "theme": theme_name,
        "url": url,
        "console": [],
        "pageerrors": [],
        "http": [],
        "blocked": [],
    }
    ctx = browser.new_context(
        viewport={"width": vp["width"], "height": vp["height"]},
        is_mobile=bool(vp.get("touch")),
        has_touch=bool(vp.get("touch")),
        color_scheme=theme.get("color_scheme"),
    )

    def route(r):
        if host_allowed(
            urlparse(r.request.url).hostname or "", allowed
        ) or r.request.url.startswith(("data:", "blob:")):
            r.continue_()
        else:
            rec["blocked"].append(r.request.url[:120])
            r.abort()

    ctx.route("**/*", route)
    host = urlparse(job["base_url"]).netloc
    b = persona.get("browser") or {}
    script = storage_script(
        host,
        {**(b.get("session_storage") or {}), **(theme.get("session_storage") or {})},
        {**(b.get("local_storage") or {}), **(theme.get("local_storage") or {})},
    )
    if script:
        ctx.add_init_script(script)
    page = ctx.new_page()
    page.on("console", lambda m: m.type == "error" and rec["console"].append(m.text[:240]))
    page.on("pageerror", lambda e: rec["pageerrors"].append(str(e)[:240]))
    page.on(
        "response",
        lambda r: (
            r.status >= 400
            and "/api/" in r.url
            and rec["http"].append(f"{r.status} {r.request.method} {urlparse(r.url).path[:100]}")
        ),
    )
    try:
        # Screens that restore from in-app state (a review, a wizard step) are
        # reached through the pages a user would pass first.
        for via in screen.get("via") or []:
            page.goto(
                job["base_url"].rstrip("/") + "/" + via.lstrip("/"),
                wait_until="domcontentloaded",
                timeout=60_000,
            )
            page.wait_for_load_state("networkidle", timeout=30_000)
    except Exception as exc:  # noqa: BLE001
        rec["via_error"] = str(exc).splitlines()[0][:200]
    t0 = time.time()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=60_000)
        ready = screen.get("ready") or {}
        timeout = float(ready.get("timeout", 30)) * 1000
        if ready.get("text"):
            page.get_by_text(re.compile(ready["text"], re.I)).first.wait_for(timeout=timeout)
        elif ready.get("selector"):
            page.locator(ready["selector"]).first.wait_for(timeout=timeout)
        else:
            page.wait_for_load_state("networkidle", timeout=timeout)
        rec["ready_s"] = round(time.time() - t0, 2)
        page.wait_for_timeout(int(job.get("settle_ms", 800)))
        rec["final_path"] = urlparse(page.url).path
        expected = urlparse(url).path
        rec["redirected"] = rec["final_path"].rstrip("/") != expected.rstrip("/")
    except Exception as exc:  # noqa: BLE001 - a screen that never gets ready is a result
        rec["ready_s"] = None
        rec["error"] = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
        rec["final_path"] = urlparse(page.url).path
        rec["redirected"] = rec["final_path"].rstrip("/") != urlparse(url).path.rstrip("/")
    try:
        page.add_script_tag(content=axe_js)
        axe = page.evaluate(
            "async (tags) => await axe.run(document, {runOnly: {type: 'tag', values: tags}, resultTypes: ['violations']})",
            axe_tags,
        )
        rec["a11y"] = [
            {
                "id": v["id"],
                "impact": v.get("impact"),
                "help": v["help"],
                "count": len(v["nodes"]),
                "sample": (v["nodes"][0].get("target") or [""])[0] if v["nodes"] else "",
            }
            for v in axe["violations"]
            if v["id"] not in axe_ignore and (v.get("impact") in impacts)
        ]
    except Exception as exc:  # noqa: BLE001
        rec["a11y_error"] = str(exc)[:200]
    try:
        rec["layout"] = page.evaluate(LAYOUT_JS, {"touch": bool(vp.get("touch"))})
    except Exception as exc:  # noqa: BLE001
        rec["layout_error"] = str(exc)[:200]
    shot = shots / f"{key}.png"
    page.screenshot(path=str(shot))
    rec["shot"] = str(shot.relative_to(shots.parent.parent))
    if baseline:
        base = baseline / f"{key}.png"
        if base.exists():
            ratio = diff_ratio(base, shot)
            rec["diff"] = None if ratio is None else round(ratio, 4)
            rec["changed"] = ratio is not None and ratio > diff_threshold
        else:
            rec["diff"] = "no-baseline"
    ctx.close()
    return rec


def main() -> None:
    job = json.loads(Path(sys.argv[1]).read_text())
    out = run_job(job)
    Path(sys.argv[2]).write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
