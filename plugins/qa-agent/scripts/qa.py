#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml>=6", "httpx>=0.27", "psycopg[binary]>=3.2"]
# ///
"""qa-agent runner: the deterministic half of the QA agent.

The /qa skill decides *what* to test; this script does the parts that must not
depend on model judgment: booting the app from its profile, logging personas
in, guarded HTTP calls, read-only SQL, recording findings and rendering the
report. Every network call it makes is checked against the profile's
``allowed_hosts`` first.

State for the active run lives in ``<project>/.qa/current.json``; artifacts
(logs, evidence, findings, report) in ``<project>/.qa/runs/<timestamp>/``.

Usage: ``qa.py <command> --help``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

DEFAULT_ALLOWED_HOSTS = ["localhost", "127.0.0.1", "::1"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
KINDS = ["bug", "security", "ux", "data", "flake-suspect"]
CONFIDENCE = ["confirmed", "likely", "speculative"]
MAX_EVIDENCE_BODY = 20_000


class QAError(Exception):
    pass


# --------------------------------------------------------------------------
# Locating the project, profile and run state
# --------------------------------------------------------------------------


def project_root(start: Path | None = None) -> Path:
    start = (start or Path.cwd()).resolve()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start,
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(out.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return start


def find_profile(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.is_file():
            raise QAError(f"profile not found: {p}")
        return p
    root = project_root()
    for candidate in (root / "qa" / "profile.yaml", root / "qa" / "profile.yml"):
        if candidate.is_file():
            return candidate
    raise QAError(
        f"no qa/profile.yaml under {root}. Create one (see the plugin's "
        "templates/profile.example.yaml) or pass --profile."
    )


def state_path() -> Path:
    return project_root() / ".qa" / "current.json"


def load_state(required: bool = True) -> dict[str, Any] | None:
    p = state_path()
    if not p.is_file():
        if required:
            raise QAError("no active run. Start one with: qa.py start")
        return None
    return json.loads(p.read_text())


def save_state(state: dict[str, Any]) -> None:
    p = state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2))


def load_profile(path: Path) -> dict[str, Any]:
    import yaml

    data = yaml.safe_load(path.read_text()) or {}
    errors = validate_profile(data)
    if errors:
        raise QAError("invalid profile:\n  - " + "\n  - ".join(errors))
    return data


def profile_root(profile_path: Path) -> Path:
    """The directory a profile's relative paths resolve against: the repo root."""
    parent = profile_path.parent
    return parent.parent if parent.name == "qa" else parent


def validate_profile(p: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(p.get("name"), str):
        errors.append("`name` (string) is required")
    urls = p.get("urls")
    if not isinstance(urls, dict) or not urls:
        errors.append("`urls` (map of name -> base URL) is required")
    hosts = p.get("allowed_hosts", DEFAULT_ALLOWED_HOSTS)
    if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
        errors.append("`allowed_hosts` must be a list of hostnames")
    elif isinstance(urls, dict):
        for key, url in urls.items():
            host = urlparse(str(url)).hostname or ""
            if not host_allowed(host, hosts):
                errors.append(f"urls.{key} host {host!r} is not in allowed_hosts")
    for i, svc in enumerate(p.get("services", []) or []):
        if not isinstance(svc, dict) or "name" not in svc:
            errors.append(f"services[{i}] needs a `name`")
        elif not any(k in svc for k in ("start", "run", "check", "ready")):
            errors.append(f"services[{i}] ({svc['name']}) needs start/run/check/ready")
    for name, persona in (p.get("personas") or {}).items():
        if not isinstance(persona, dict):
            errors.append(f"personas.{name} must be a map")
    seen: set[str] = set()
    for section in ("journeys", "invariants", "charters"):
        for i, item in enumerate(p.get(section, []) or []):
            if not isinstance(item, dict) or "id" not in item:
                errors.append(f"{section}[{i}] needs an `id`")
                continue
            if item["id"] in seen:
                errors.append(f"duplicate id {item['id']!r}")
            seen.add(item["id"])
    return errors


# --------------------------------------------------------------------------
# Templating and host guard
# --------------------------------------------------------------------------

_TEMPLATE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_.:-]*)\}")
_ENV_TEMPLATE = re.compile(r"\{env:([A-Za-z_][A-Za-z0-9_]*)(?:\|([^}]*))?\}")


def render(value: Any, ctx: dict[str, Any]) -> Any:
    """Substitute ``{key}``, ``{urls.api}``, ``{env:VAR}`` and ``{env:VAR|default}``.

    Unknown keys are left untouched so literal braces in JSON survive.
    """
    if isinstance(value, str):
        value = _ENV_TEMPLATE.sub(
            lambda m: os.environ.get(
                m.group(1), m.group(2) if m.group(2) is not None else m.group(0)
            ),
            value,
        )

        def sub(m: re.Match[str]) -> str:
            key = m.group(1)
            if key.startswith("env:"):
                return os.environ.get(key[4:], m.group(0))
            cur: Any = ctx
            for part in key.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    return m.group(0)
            return str(cur)

        return _TEMPLATE.sub(sub, value)
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value


def host_allowed(host: str, allowed: list[str]) -> bool:
    host = (host or "").lower().strip("[]")
    for pattern in allowed:
        pattern = pattern.lower()
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]):
                return True
        elif host == pattern:
            return True
    return False


def guard(url: str, allowed: list[str]) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise QAError(f"refusing non-http URL: {url}")
    if not host_allowed(parsed.hostname or "", allowed):
        raise QAError(
            f"BLOCKED: {parsed.hostname} is not in this profile's allowed_hosts "
            f"{allowed}. The QA agent never talks to hosts outside the profile."
        )


# --------------------------------------------------------------------------
# Run context
# --------------------------------------------------------------------------


class Run:
    def __init__(self, state: dict[str, Any]):
        self.state = state
        self.profile_path = Path(state["profile"])
        self.profile = load_profile(self.profile_path)
        self.root = profile_root(self.profile_path)
        self.dir = Path(state["run_dir"])
        self.allowed = self.profile.get("allowed_hosts", DEFAULT_ALLOWED_HOSTS)

    @property
    def ctx(self) -> dict[str, Any]:
        return {
            "urls": self.profile.get("urls", {}),
            "root": str(self.root),
            "run_dir": str(self.dir),
            "repos": {k: str((self.root / v).resolve()) for k, v in self.repos.items()},
        }

    @property
    def repos(self) -> dict[str, str]:
        """name -> path; a repo entry is a path or ``{path, diff_base}``."""
        raw = self.profile.get("repos", {}) or {}
        return {k: v["path"] if isinstance(v, dict) else v for k, v in raw.items()}

    def repo_base(self, name: str, default: str) -> str:
        entry = (self.profile.get("repos", {}) or {}).get(name)
        return entry.get("diff_base", default) if isinstance(entry, dict) else default

    def env(self, extra: dict[str, Any] | None = None) -> dict[str, str]:
        env = dict(os.environ)
        for src in (self.profile.get("env") or {}, extra or {}):
            for k, v in render(src, self.ctx).items():
                env[str(k)] = str(v)
        return env

    def save(self) -> None:
        save_state(self.state)

    def next_evidence(self, prefix: str) -> Path:
        ev = self.dir / "evidence"
        ev.mkdir(parents=True, exist_ok=True)
        n = len(list(ev.glob(f"{prefix}-*.json"))) + 1
        return ev / f"{prefix}-{n:04d}.json"


def current_run() -> Run:
    return Run(load_state())


# --------------------------------------------------------------------------
# Commands: start / status / stop
# --------------------------------------------------------------------------


def cmd_start(args: argparse.Namespace) -> None:
    profile_path = find_profile(args.profile)
    profile = load_profile(profile_path)
    root = project_root()
    existing = load_state(required=False)
    if existing and not args.force:
        raise QAError(
            f"a run is already active ({existing['run_dir']}). "
            "Finish it with `qa.py report` + `qa.py stop`, or pass --force."
        )
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = root / ".qa" / "runs" / stamp
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    gitignore = root / ".qa" / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("*\n")
    state = {
        "profile": str(profile_path),
        "run_dir": str(run_dir),
        "started_at": dt.datetime.now().isoformat(timespec="seconds"),
        "mode": args.mode,
        "pids": {},
        "tokens": {},
    }
    save_state(state)
    print(f"run started: {run_dir}")
    print(f"profile: {profile['name']} ({profile_path})")
    print(f"allowed_hosts: {profile.get('allowed_hosts', DEFAULT_ALLOWED_HOSTS)}")


def cmd_status(_: argparse.Namespace) -> None:
    run = current_run()
    print(json.dumps({k: v for k, v in run.state.items() if k != "tokens"}, indent=2))
    print("logged in:", ", ".join(run.state.get("tokens", {})) or "nobody")


def _shell(cmd: str, cwd: Path, env: dict[str, str], log: Path | None = None) -> int:
    out = open(log, "a") if log else None
    try:
        return subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            env=env,
            stdout=out or subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        ).returncode
    finally:
        if out:
            out.close()


def _ready(svc: dict[str, Any], run: Run, cwd: Path, env: dict[str, str]) -> bool:
    ready = render(svc.get("ready"), run.ctx)
    if not ready:
        return False
    if "http" in ready:
        import httpx

        url = ready["http"]
        guard(url, run.allowed)
        try:
            r = httpx.get(url, timeout=3, follow_redirects=True)
            return r.status_code < 500
        except httpx.HTTPError:
            return False
    if "cmd" in ready:
        return _shell(ready["cmd"], cwd, env) == 0
    return False


def cmd_up(args: argparse.Namespace) -> None:
    run = current_run()
    only = set(args.only.split(",")) if args.only else None
    for svc in run.profile.get("services", []) or []:
        name = svc["name"]
        if only and name not in only:
            continue
        cwd = (run.root / render(svc.get("cwd", "."), run.ctx)).resolve()
        env = run.env(svc.get("env"))
        log = run.dir / "logs" / f"{name}.log"
        if svc.get("check") and _shell(render(svc["check"], run.ctx), cwd, env) == 0:
            print(f"[{name}] already up (check passed)")
            continue
        if svc.get("ready") and not svc.get("run") and _ready(svc, run, cwd, env):
            print(f"[{name}] already up (ready)")
            continue
        if svc.get("run"):
            print(f"[{name}] running: {svc['run']}")
            code = _shell(render(svc["run"], run.ctx), cwd, env, log)
            if code != 0:
                raise QAError(f"[{name}] exited {code}; see {log}")
            continue
        if svc.get("start"):
            cmd = render(svc["start"], run.ctx)
            if svc.get("background", True):
                print(f"[{name}] starting in background: {cmd}")
                with open(log, "a") as fh:
                    proc = subprocess.Popen(
                        cmd,
                        shell=True,
                        cwd=cwd,
                        env=env,
                        stdout=fh,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                run.state["pids"][name] = proc.pid
                run.save()
            else:
                print(f"[{name}] starting: {cmd}")
                code = _shell(cmd, cwd, env, log)
                if code != 0:
                    raise QAError(f"[{name}] exited {code}; see {log}")
        if svc.get("ready"):
            timeout = float((svc.get("ready") or {}).get("timeout", 90))
            deadline = time.time() + timeout
            while time.time() < deadline:
                if _ready(svc, run, cwd, env):
                    print(f"[{name}] ready")
                    break
                pid = run.state["pids"].get(name)
                if pid and not _alive(pid):
                    raise QAError(f"[{name}] died during startup; see {log}")
                time.sleep(1)
            else:
                raise QAError(f"[{name}] not ready after {timeout:.0f}s; see {log}")
    print("all services up")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def cmd_stop(args: argparse.Namespace) -> None:
    state = load_state(required=False)
    if not state:
        print("no active run")
        return
    for name, pid in (state.get("pids") or {}).items():
        try:
            os.killpg(pid, signal.SIGTERM)
            for _ in range(20):
                if not _alive(pid):
                    break
                time.sleep(0.25)
            else:
                os.killpg(pid, signal.SIGKILL)
            print(f"[{name}] stopped")
        except ProcessLookupError:
            print(f"[{name}] already gone")
    state_path().unlink()
    print(f"run closed. Artifacts kept in {state['run_dir']}")


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


def _extract(data: Any, path: str) -> Any:
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(path)
    return cur


def _persona(run: Run, name: str) -> dict[str, Any]:
    personas = run.profile.get("personas") or {}
    if name not in personas:
        raise QAError(f"unknown persona {name!r}; profile has: {', '.join(personas)}")
    return personas[name]


def _auth_headers(run: Run, persona: str | None) -> dict[str, str]:
    if not persona or persona == "anon":
        return {}
    token = run.state.get("tokens", {}).get(persona)
    if token is None:
        raise QAError(f"persona {persona!r} is not logged in. Run: qa.py login {persona}")
    spec = _persona(run, persona)
    ctx = {**run.ctx, "token": token}
    headers = spec.get("headers") or {"Authorization": "Bearer {token}"}
    return render(headers, ctx)


def http_request(
    run: Run,
    method: str,
    path: str,
    persona: str | None = None,
    json_body: Any = None,
    form: dict[str, str] | None = None,
    files: dict[str, str] | None = None,
    query: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    base: str = "api",
) -> tuple[Any, Path, Any]:
    """Send one guarded request; returns (response, evidence path, parsed body)."""
    import httpx

    urls = run.profile.get("urls", {})
    if path.startswith(("http://", "https://")):
        url = path
    else:
        if base not in urls:
            raise QAError(f"profile has no urls.{base}")
        url = urljoin(urls[base].rstrip("/") + "/", path.lstrip("/"))
    guard(url, run.allowed)
    hdrs = {**_auth_headers(run, persona), **(headers or {})}
    opened = []
    try:
        file_payload = None
        if files:
            file_payload = {}
            for field, fpath in files.items():
                fp = (Path.cwd() / fpath).resolve()
                fh = open(fp, "rb")
                opened.append(fh)
                file_payload[field] = (fp.name, fh)
        with httpx.Client(timeout=120, follow_redirects=False) as client:
            resp = client.request(
                method.upper(),
                url,
                json=json_body,
                data=form,
                files=file_payload,
                params=query,
                headers=hdrs,
            )
    finally:
        for fh in opened:
            fh.close()
    ctype = resp.headers.get("content-type", "")
    if "json" in ctype:
        try:
            body: Any = resp.json()
        except ValueError:
            body = resp.text
    elif ctype.startswith("text/") or not resp.content:
        body = resp.text
    else:
        body = f"<{len(resp.content)} bytes of {ctype}>"
    evidence = run.next_evidence("http")
    record = {
        "at": dt.datetime.now().isoformat(timespec="seconds"),
        "persona": persona or "anon",
        "request": {
            "method": method.upper(),
            "url": str(resp.request.url),
            "json": json_body,
            "form": form,
            "files": files,
        },
        "response": {
            "status": resp.status_code,
            "content_type": ctype,
            "body": body
            if len(json.dumps(body, default=str)) <= MAX_EVIDENCE_BODY
            else json.dumps(body, default=str)[:MAX_EVIDENCE_BODY] + "…(truncated)",
        },
    }
    evidence.write_text(json.dumps(record, indent=2, default=str))
    return resp, evidence, body


def _kv(items: list[str] | None) -> dict[str, str] | None:
    if not items:
        return None
    out = {}
    for item in items:
        if "=" not in item:
            raise QAError(f"expected key=value, got {item!r}")
        k, v = item.split("=", 1)
        out[k] = v
    return out


def _print_body(body: Any, limit: int) -> None:
    text = body if isinstance(body, str) else json.dumps(body, indent=2, default=str)
    if len(text) > limit:
        text = text[:limit] + f"\n…(truncated, {len(text)} chars; full body in evidence)"
    print(text)


def cmd_http(args: argparse.Namespace) -> None:
    run = current_run()
    json_body = json.loads(args.json) if args.json else None
    resp, evidence, body = http_request(
        run,
        args.method,
        args.path,
        persona=args.as_,
        json_body=json_body,
        form=_kv(args.form),
        files=_kv(args.file),
        query=_kv(args.query),
        headers=_kv(args.header),
        base=args.base,
    )
    rel = evidence.relative_to(run.dir)
    print(
        f"HTTP {resp.status_code} {args.method.upper()} {resp.request.url} "
        f"as={args.as_ or 'anon'} evidence={rel}"
    )
    _print_body(body, args.max)


# --------------------------------------------------------------------------
# Reset / login
# --------------------------------------------------------------------------


def _run_step(run: Run, step: dict[str, Any], ctx: dict[str, Any]) -> Any:
    step = render(step, ctx)
    if "http" in step:
        h = step["http"]
        resp, evidence, body = http_request(
            run,
            h.get("method", "GET"),
            h["path"],
            persona=h.get("as"),
            json_body=h.get("json"),
            form=h.get("form"),
            query=h.get("query"),
            headers=h.get("headers"),
            base=h.get("base", "api"),
        )
        expect = h.get("expect", [200, 201, 204])
        if resp.status_code not in (expect if isinstance(expect, list) else [expect]):
            raise QAError(
                f"step {h['method']} {h['path']} returned {resp.status_code} "
                f"(expected {expect}); evidence {evidence}"
            )
        return body
    if "cmd" in step:
        cwd = (run.root / step.get("cwd", ".")).resolve()
        out = subprocess.run(
            step["cmd"], shell=True, cwd=cwd, env=run.env(), capture_output=True, text=True
        )
        if out.returncode != 0:
            raise QAError(f"step `{step['cmd']}` failed ({out.returncode}):\n{out.stderr[-2000:]}")
        try:
            return json.loads(out.stdout)
        except ValueError:
            return out.stdout.strip()
    raise QAError(f"step needs `http` or `cmd`: {step}")


def cmd_reset(_: argparse.Namespace) -> None:
    run = current_run()
    steps = run.profile.get("reset") or []
    if not steps:
        raise QAError("profile defines no `reset` steps")
    for step in steps:
        _run_step(run, step, run.ctx)
    run.state["tokens"] = {}
    run.save()
    print("reset done; all personas logged out (log in again)")


def cmd_login(args: argparse.Namespace) -> None:
    run = current_run()
    names = args.persona or list((run.profile.get("personas") or {}).keys())
    for name in names:
        spec = _persona(run, name)
        login = spec.get("login")
        if not login:
            raise QAError(f"personas.{name} has no `login` step")
        result = _run_step(run, login, run.ctx)
        token_path = spec.get("token", "token")
        try:
            token = _extract(result, token_path) if isinstance(result, (dict, list)) else result
        except (KeyError, IndexError, ValueError) as exc:
            raise QAError(f"login for {name}: no `{token_path}` in response {result!r}") from exc
        run.state.setdefault("tokens", {})[name] = token
        run.state.setdefault("persona_data", {})[name] = result if isinstance(result, dict) else {}
        run.save()
        print(f"[{name}] logged in")
        if isinstance(result, dict):
            visible = {k: v for k, v in result.items() if "token" not in k.lower()}
            if visible:
                print(f"  identity: {json.dumps(visible)}")
        browser = spec.get("browser")
        if browser:
            ctx = {**run.ctx, "token": token}
            b = render(browser, ctx)
            print("  browser sign-in (Playwright MCP):")
            print(f"    1. browser_navigate {b.get('url', run.profile['urls'].get('web', ''))}")
            snippet = _storage_snippet(b)
            if snippet:
                print(f"    2. browser_evaluate  {snippet}")
                print("    3. browser_navigate to the same URL again (reload picks up the session)")


def _storage_snippet(b: dict[str, Any]) -> str:
    parts = []
    for area, store in (
        ("sessionStorage", b.get("session_storage")),
        ("localStorage", b.get("local_storage")),
    ):
        for k, v in (store or {}).items():
            parts.append(f"{area}.setItem({json.dumps(k)}, {json.dumps(v)})")
    if not parts:
        return ""
    return "() => { " + "; ".join(parts) + "; }"


def cmd_token(args: argparse.Namespace) -> None:
    run = current_run()
    token = run.state.get("tokens", {}).get(args.persona)
    if token is None:
        raise QAError(f"{args.persona} is not logged in")
    print(token)


# --------------------------------------------------------------------------
# SQL (read-only)
# --------------------------------------------------------------------------


def cmd_sql(args: argparse.Namespace) -> None:
    import psycopg

    run = current_run()
    db = run.profile.get("database") or {}
    url = render(db.get("url", ""), run.ctx)
    if db.get("url_env"):
        url = run.env().get(db["url_env"], url)
    if not url:
        raise QAError("profile has no `database.url` / `database.url_env`")
    host = urlparse(url.replace("postgresql+psycopg", "postgresql")).hostname or ""
    if not host_allowed(host, run.allowed):
        raise QAError(f"BLOCKED: database host {host!r} is not in allowed_hosts")
    url = re.sub(r"^postgresql\+\w+://", "postgresql://", url)
    query = args.query.strip().rstrip(";")
    # A prepared statement rejects multiple commands (no `commit; delete`),
    # and the session defaults to read-only: writes fail at the server.
    try:
        with psycopg.connect(
            url, autocommit=False, options="-c default_transaction_read_only=on"
        ) as conn:
            conn.read_only = True
            with conn.cursor() as cur:
                cur.execute(query, prepare=True)
                cols = [c.name for c in cur.description] if cur.description else []
                rows = cur.fetchmany(args.limit) if cols else []
            conn.rollback()
    except psycopg.Error as exc:
        raise QAError(f"sql refused: {type(exc).__name__}: {str(exc).strip()}") from exc
    evidence = run.next_evidence("sql")
    data = [dict(zip(cols, r, strict=False)) for r in rows]
    evidence.write_text(json.dumps({"query": query, "rows": data}, indent=2, default=str))
    print(f"{len(data)} row(s) evidence={evidence.relative_to(run.dir)}")
    for row in data:
        print(json.dumps(row, default=str))


# --------------------------------------------------------------------------
# Plan (what to test)
# --------------------------------------------------------------------------


def _glob_re(pattern: str) -> re.Pattern[str]:
    i, out = 0, ""
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + "$")


def _changed_files(repo: Path, base: str) -> list[str]:
    files: set[str] = set()
    cmds = [
        ["git", "diff", "--name-only", f"{base}...HEAD"],
        ["git", "diff", "--name-only", "HEAD"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    ]
    for c in cmds:
        out = subprocess.run(c, cwd=repo, capture_output=True, text=True)
        if out.returncode == 0:
            files.update(line for line in out.stdout.splitlines() if line)
    return sorted(files)


def cmd_plan(args: argparse.Namespace) -> None:
    run = current_run()
    p = run.profile
    sections = {s: list(p.get(s, []) or []) for s in ("journeys", "invariants", "charters")}
    selected: dict[str, list[dict[str, Any]]] = {s: [] for s in sections}
    reason = "full run"
    if args.only:
        wanted = set(args.only.split(","))
        for s, items in sections.items():
            selected[s] = [i for i in items if i["id"] in wanted]
        reason = f"--only {args.only}"
    elif args.changed:
        base = args.base or p.get("diff_base", "origin/main")
        changed = _changed_files(run.root, base)
        for name, rel in run.repos.items():
            repo = (run.root / rel).resolve()
            if repo.is_dir():
                repo_base = args.base or run.repo_base(name, base)
                changed += [f"{name}:{f}" for f in _changed_files(repo, repo_base)]
        print(f"changed files vs {base}: {len(changed)}")
        for f in changed[:50]:
            print(f"  {f}")
        for s, items in sections.items():
            for item in items:
                pats = item.get("paths") or []
                hit = any(_glob_re(pt).match(f) for pt in pats for f in changed)
                if hit or item.get("always"):
                    selected[s].append(item)
        if not any(selected.values()):
            for s, items in sections.items():
                selected[s] = [i for i in items if i.get("smoke")]
            reason = "no path matched; running smoke items"
        else:
            reason = f"diff-aware vs {base}"
    else:
        selected = sections
        if not args.include_charters:
            selected = {**sections, "charters": []}
    import yaml

    print(f"plan: {reason}")
    out = {s: v for s, v in selected.items() if v}
    print(yaml.safe_dump(out, sort_keys=False, width=100))
    run.state["plan"] = {s: [i["id"] for i in v] for s, v in selected.items()}
    run.save()


# --------------------------------------------------------------------------
# Coverage, findings, report
# --------------------------------------------------------------------------


def _append(path: Path, record: dict[str, Any]) -> None:
    with open(path, "a") as fh:
        fh.write(json.dumps(record, default=str) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def cmd_cover(args: argparse.Namespace) -> None:
    run = current_run()
    _append(
        run.dir / "coverage.jsonl",
        {
            "id": args.id,
            "result": args.result,
            "note": args.note or "",
            "at": dt.datetime.now().isoformat(timespec="seconds"),
        },
    )
    print(f"{args.id}: {args.result}")


def cmd_finding(args: argparse.Namespace) -> None:
    run = current_run()
    raw = args.json if args.json != "-" else sys.stdin.read()
    f = json.loads(raw)
    required = ["title", "severity", "kind", "item", "steps", "expected", "actual"]
    missing = [k for k in required if not f.get(k)]
    if missing:
        raise QAError(f"finding missing {missing}. Required: {required}")
    if f["severity"] not in SEVERITIES:
        raise QAError(f"severity must be one of {SEVERITIES}")
    if f["kind"] not in KINDS:
        raise QAError(f"kind must be one of {KINDS}")
    f.setdefault("confidence", "likely")
    if f["confidence"] not in CONFIDENCE:
        raise QAError(f"confidence must be one of {CONFIDENCE}")
    if isinstance(f["steps"], str):
        f["steps"] = [f["steps"]]
    existing = _read_jsonl(run.dir / "findings.jsonl")
    f["id"] = f"F{len(existing) + 1:03d}"
    f["at"] = dt.datetime.now().isoformat(timespec="seconds")
    _append(run.dir / "findings.jsonl", f)
    print(f"recorded {f['id']}: [{f['severity']}] {f['title']}")


def cmd_report(_: argparse.Namespace) -> None:
    run = current_run()
    findings = _read_jsonl(run.dir / "findings.jsonl")
    coverage = _read_jsonl(run.dir / "coverage.jsonl")
    latest: dict[str, dict[str, Any]] = {}
    for c in coverage:
        latest[c["id"]] = c
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: order.get(f["severity"], 99))
    p = run.profile
    lines = [
        f"# QA report: {p['name']}",
        "",
        f"- Run: `{run.dir.name}` (started {run.state.get('started_at')}, mode {run.state.get('mode')})",
        f"- Profile: `{run.profile_path}`",
        f"- Findings: {len(findings)} "
        + "("
        + ", ".join(
            f"{s}: {sum(1 for f in findings if f['severity'] == s)}"
            for s in SEVERITIES
            if any(f["severity"] == s for f in findings)
        )
        + ")"
        if findings
        else "- Findings: none",
        "",
        "## Coverage",
        "",
        "| Item | Result | Note |",
        "|---|---|---|",
    ]
    planned = [i for ids in (run.state.get("plan") or {}).values() for i in ids]
    for item_id in planned + [i for i in latest if i not in planned]:
        c = latest.get(item_id)
        result = c["result"] if c else "not run"
        note = (c or {}).get("note", "").replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{item_id}` | {result} | {note} |")
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No findings.")
    for f in findings:
        lines += [
            f"### {f['id']} [{f['severity']}/{f['kind']}] {f['title']}",
            "",
            f"- Item: `{f['item']}`  Confidence: {f['confidence']}",
        ]
        if f.get("persona"):
            lines.append(f"- Persona: {f['persona']}")
        if f.get("suspect"):
            lines.append(f"- Suspected code: `{f['suspect']}`")
        lines += ["", "**Steps to reproduce**", ""]
        lines += [f"{n}. {s}" for n, s in enumerate(f["steps"], 1)]
        lines += ["", f"**Expected:** {f['expected']}", "", f"**Actual:** {f['actual']}", ""]
        if f.get("evidence"):
            lines.append("**Evidence:** " + ", ".join(f"`{e}`" for e in f["evidence"]))
            lines.append("")
        if f.get("regression_test"):
            lines += ["**Proposed regression test**", "", "```", f["regression_test"], "```", ""]
    report = run.dir / "report.md"
    report.write_text("\n".join(lines) + "\n")
    (run.dir / "report.json").write_text(
        json.dumps(
            {
                "profile": p["name"],
                "run": run.dir.name,
                "coverage": list(latest.values()),
                "findings": findings,
            },
            indent=2,
            default=str,
        )
    )
    print(f"report: {report}")
    print(f"json:   {run.dir / 'report.json'}")


# --------------------------------------------------------------------------
# Hook: guard browser navigation
# --------------------------------------------------------------------------


def _urls_in(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and (k.lower() in ("url", "href") or re.match(r"^[a-z]+://", v)):
                found.append(v)
            else:
                found += _urls_in(v)
    elif isinstance(obj, list):
        for v in obj:
            found += _urls_in(v)
    return found


def cmd_guard_url(_: argparse.Namespace) -> None:
    """PreToolUse hook: block browser tools from leaving allowed_hosts (exit 2)."""
    try:
        event = json.load(sys.stdin)
    except ValueError:
        sys.exit(0)
    allowed = DEFAULT_ALLOWED_HOSTS
    cwd = event.get("cwd")
    try:
        if cwd:
            os.chdir(cwd)
        state = load_state(required=False)
        if state:
            allowed = load_profile(Path(state["profile"])).get("allowed_hosts", allowed)
    except Exception:  # noqa: BLE001 - a broken profile must not open the guard
        allowed = DEFAULT_ALLOWED_HOSTS
    for url in _urls_in(event.get("tool_input") or {}):
        parsed = urlparse(url)
        if parsed.scheme in ("about", "data", "blob", "javascript"):
            continue
        if parsed.scheme not in ("http", "https") or not host_allowed(
            parsed.hostname or "", allowed
        ):
            print(
                f"qa-agent blocked {url}: host not in allowed_hosts {allowed}. "
                "Testing only ever targets the local/staging hosts the profile lists.",
                file=sys.stderr,
            )
            sys.exit(2)
    sys.exit(0)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="qa.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("validate", help="validate a profile and exit")
    s.add_argument("--profile")
    s.set_defaults(fn=lambda a: print(f"ok: {load_profile(find_profile(a.profile))['name']}"))

    s = sub.add_parser("start", help="open a run (does not boot anything)")
    s.add_argument("--profile")
    s.add_argument("--mode", default="manual", help="label: manual | pr | nightly | ...")
    s.add_argument("--force", action="store_true", help="replace an active run")
    s.set_defaults(fn=cmd_start)

    s = sub.add_parser("up", help="boot the profile's services (skips ones already up)")
    s.add_argument("--only", help="comma-separated service names")
    s.set_defaults(fn=cmd_up)

    sub.add_parser("status", help="show the active run").set_defaults(fn=cmd_status)

    s = sub.add_parser("stop", help="stop services this run started and close the run")
    s.set_defaults(fn=cmd_stop)

    sub.add_parser("reset", help="run the profile's reset steps").set_defaults(fn=cmd_reset)

    s = sub.add_parser("login", help="log personas in (all if none given)")
    s.add_argument("persona", nargs="*")
    s.set_defaults(fn=cmd_login)

    s = sub.add_parser("token", help="print a logged-in persona's token")
    s.add_argument("persona")
    s.set_defaults(fn=cmd_token)

    s = sub.add_parser("http", help="guarded HTTP request, saved as evidence")
    s.add_argument("method")
    s.add_argument("path", help="path relative to urls.<base>, or a full allowed URL")
    s.add_argument("--as", dest="as_", help="persona (default: anonymous)")
    s.add_argument("--json", help="JSON request body")
    s.add_argument("--form", action="append", help="form field key=value (repeatable)")
    s.add_argument("--file", action="append", help="multipart file field=path (repeatable)")
    s.add_argument("--query", action="append", help="query param key=value (repeatable)")
    s.add_argument("--header", action="append", help="extra header key=value (repeatable)")
    s.add_argument("--base", default="api", help="which urls.<name> to resolve against")
    s.add_argument("--max", type=int, default=4000, help="max chars of body to print")
    s.set_defaults(fn=cmd_http)

    s = sub.add_parser("sql", help="read-only SQL against the profile's database")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=200)
    s.set_defaults(fn=cmd_sql)

    s = sub.add_parser("plan", help="print the journeys/invariants/charters to run")
    s.add_argument("--changed", action="store_true", help="select by changed files")
    s.add_argument("--base", help="git ref to diff against (default profile.diff_base)")
    s.add_argument("--only", help="comma-separated item ids")
    s.add_argument("--include-charters", action="store_true", help="add exploratory charters")
    s.set_defaults(fn=cmd_plan)

    s = sub.add_parser("cover", help="record a journey/invariant/charter outcome")
    s.add_argument("id")
    s.add_argument("result", choices=["pass", "fail", "blocked", "skipped"])
    s.add_argument("--note")
    s.set_defaults(fn=cmd_cover)

    s = sub.add_parser("finding", help="record a finding (JSON; '-' reads stdin)")
    s.add_argument("json")
    s.set_defaults(fn=cmd_finding)

    sub.add_parser("report", help="render report.md + report.json").set_defaults(fn=cmd_report)

    sub.add_parser(
        "guard-url", help="(hook) block browser URLs outside allowed_hosts"
    ).set_defaults(fn=cmd_guard_url)

    args = ap.parse_args(argv)
    try:
        args.fn(args)
    except QAError as exc:
        print(f"qa: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
