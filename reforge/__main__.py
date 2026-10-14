"""Entry point and the small command line that automation needs.

    retrace                       start the API and the SPA (same as `retrace serve`)
    retrace serve [--host H] [--port P]
    retrace config show           the effective settings, secrets masked, as JSON
    retrace config set KEY VALUE  validate and persist one setting to STATE_ROOT/settings.json
    retrace check                 import the app, report the profile and the state directory

`config set` goes through the same `Settings` model as the file and the environment, so a value
the server would refuse is refused here too, and `team` hardening applies to it exactly as it
would at start-up. It never writes the source tree, and it never accepts a secret: those go in
the secrets store (see docs/installation.md).
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Optional

_SECRET_FIELDS = {"anthropic_api_key", "nvd_api_key", "local_api_key"}


def _parse_value(raw: str) -> Any:
    """`true`/`false`, integers, floats and JSON lists/objects are typed; anything else is text."""
    low = raw.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from . import config

    uvicorn.run("reforge.server:app", host=args.host or config.HOST,
                port=args.port or config.PORT, reload=config.RELOAD)
    return 0


def cmd_config_show(args: argparse.Namespace) -> int:
    from . import config

    payload = config.SETTINGS.model_dump(mode="json")
    for key in _SECRET_FIELDS:
        if payload.get(key):
            payload[key] = "***"
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_config_set(args: argparse.Namespace) -> int:
    from . import config, settings as settings_mod

    key = args.key.strip().lower()
    if key in _SECRET_FIELDS:
        print(f"refusing to store the secret '{key}' in settings.json; use the secrets store",
              file=sys.stderr)
        return 2
    if key not in settings_mod.Settings.model_fields:
        print(f"unknown setting '{key}'. `retrace config show` lists the valid ones.", file=sys.stderr)
        return 2
    current = config.SETTINGS.model_dump()
    try:
        candidate = settings_mod.Settings(**{**current, key: _parse_value(args.value)})
    except Exception as exc:  # pydantic ValidationError, kept generic so the message is the model's
        print(f"rejected: {exc}", file=sys.stderr)
        return 2
    path = candidate.save(config.STATE_ROOT)
    effective = getattr(candidate, key)
    note = "" if effective == _parse_value(args.value) else f"  (forced to {effective!r} by the {candidate.deployment_profile} profile)"
    print(f"{key} = {effective!r}{note}\nsaved to {path}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    from . import config
    import reforge.server as server

    s = config.SETTINGS
    print(f"retrace {getattr(__import__('reforge'), '__version__', '?')}")
    print(f"profile: {s.deployment_profile} | safety: {s.safety_mode} | egress: {s.operating_profile}")
    print(f"state dir: {config.STATE_ROOT}")
    print(f"settings file: {config.SETTINGS_FILE} ({'present' if config.SETTINGS_FILE.exists() else 'defaults'})")
    print(f"routes: {len(server.app.routes)}")
    from . import llm as _llm
    import asyncio as _asyncio
    problem = _llm.provider_problem()
    reachable, probe_error = _asyncio.run(_llm.local_reachable())
    if s.llm_provider == "none":
        print("llm: none (offline deterministic analysis only)")
    elif problem:
        print(f"llm: {s.llm_provider} - NOT READY: {problem}")
    elif reachable is False:
        print(f"llm: {s.llm_provider} - NOT READY: {s.local_base_url} is not reachable ({probe_error})")
    elif probe_error:
        print(f"llm: {s.llm_provider} - NOT READY: {probe_error}")
    else:
        print(f"llm: {s.llm_provider} ({config.active_model()}) - ready")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="retrace", description="ReTrace - binary vulnerability research workbench")
    sub = p.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="start the API and the SPA")
    serve.add_argument("--host"); serve.add_argument("--port", type=int)
    serve.set_defaults(func=cmd_serve)
    cfg = sub.add_parser("config", help="show or change settings")
    cfg_sub = cfg.add_subparsers(dest="config_command")
    cfg_sub.add_parser("show", help="effective settings as JSON").set_defaults(func=cmd_config_show)
    st = cfg_sub.add_parser("set", help="validate and persist one setting")
    st.add_argument("key"); st.add_argument("value"); st.set_defaults(func=cmd_config_set)
    sub.add_parser("check", help="import the app and report profile, state dir, routes").set_defaults(func=cmd_check)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """Exposed as the `retrace` console script. No subcommand means `serve`."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        args.host = None; args.port = None
        return cmd_serve(args)
    if args.command == "config" and args.config_command is None:
        parser.parse_args(["config", "--help"])
        return 2
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
