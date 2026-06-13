"""
configctl - Command line interface for the configclient configuration center.

Standard library only.
"""

import os
import sys
import json
import time
import argparse
import threading
import signal
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import configclient
from configclient import (
    ConfigClient,
    banner,
    log_info,
    log_warn,
    log_error,
    load_cache,
    save_cache,
    load_history,
    list_history_versions,
    save_history,
    fetch_remote,
    push_remote,
    validate_config,
    require_crypto_key,
    cache_dir,
    cache_path,
    EXIT_OK,
    EXIT_ARG_ERROR,
    EXIT_REMOTE_ERROR,
    EXIT_VALIDATION_ERROR,
    EXIT_PERMISSION_ERROR,
    EXIT_IO_ERROR,
    __version__,
)


MOCK_DEFAULT_CONFIG = {
    "version": 1,
    "updated_at": "2025-01-01T00:00:00.000Z",
    "db": {
        "host": "db.internal",
        "port": 5432,
        "user": "app",
    },
    "api": {
        "url": "https://api.example.com",
        "secret": "enc://v1:placeholder",
    },
    "feature_flags": {
        "new_ui": True,
        "beta_mode": False,
    },
    "timeout": 30,
}


class MockConfigHandler(BaseHTTPRequestHandler):
    server_version = "configctl-mock/1.0"

    def log_message(self, format, *args):
        log_info(f"[mock] {self.address_string()} - {format % args}")

    def _send_json(self, status: int, data: dict, etag: Optional[str] = None):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/api/config", "/config"):
            import hashlib
            body_str = json.dumps(MOCK_DEFAULT_CONFIG, ensure_ascii=False, sort_keys=True)
            etag = '"' + hashlib.md5(body_str.encode("utf-8")).hexdigest() + '"'
            if_none_match = self.headers.get("If-None-Match")
            if if_none_match and if_none_match == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.end_headers()
                return
            self._send_json(200, MOCK_DEFAULT_CONFIG, etag=etag)
        else:
            self._send_json(404, {"error": "not found"})

    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path not in ("/", "/api/config", "/config"):
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            raw = self.rfile.read(length)
            cfg = json.loads(raw.decode("utf-8"))
            ok, errs = validate_config(cfg)
            if not ok:
                self._send_json(400, {"error": "validation failed", "details": errs})
                return
            global MOCK_DEFAULT_CONFIG
            MOCK_DEFAULT_CONFIG = cfg
            log_info(f"[mock] Config updated to version {cfg.get('version')}")
            self._send_json(200, {"ok": True, "version": cfg.get("version")})
        except Exception as e:
            self._send_json(400, {"error": f"bad request: {e}"})


def _run_mock_server(host: str, port: int, stop_event: threading.Event):
    server = HTTPServer((host, port), MockConfigHandler)
    log_info(f"Mock remote server listening on http://{host}:{port}")
    try:
        while not stop_event.is_set():
            server.timeout = 0.5
            server.handle_request()
    finally:
        server.server_close()
        log_info("Mock remote server stopped")


def cmd_run(args) -> int:
    if args.require_key:
        require_crypto_key()

    source_used = "none"
    load_errors = []

    client = ConfigClient(remote_url=args.remote, dry_run=args.dry_run)

    ok, err = client.load_from_cache()
    if ok:
        source_used = "cache"
        log_info("Loaded configuration from local cache (fast path)")
    elif err:
        load_errors.append(f"Cache: {err}")

    if args.mock_remote:
        mock_cfg = dict(MOCK_DEFAULT_CONFIG)
        ok_m, errs_m = validate_config(mock_cfg)
        if ok_m:
            client._apply_config(mock_cfg, "mock")
            source_used = "mock"
            log_info("Loaded mock configuration")
        else:
            for e in errs_m:
                log_warn(f"Mock config validation warning: {e}")

    one_shot_mode = args.print_config or args.dry_run

    if args.remote and not args.mock_remote:
        if one_shot_mode:
            ok_r, err_r = client.load_from_remote(save_history_flag=True)
            if ok_r:
                if client.config_source == "remote" or source_used == "none":
                    source_used = "remote"
                log_info("Loaded configuration from remote endpoint (synchronous)")
            elif err_r:
                load_errors.append(f"Remote: {err_r}")
                log_warn(f"Remote fetch failed: {err_r}")
        else:
            client.load_from_remote_async(save_history_flag=True)
            log_info("Remote fetch running in background, will update when ready")

    if not client.is_loaded:
        log_error("Failed to load configuration from any source.")
        for e in load_errors:
            log_error(f"  - {e}")
        if args.remote and not args.mock_remote and source_used == "none":
            return EXIT_REMOTE_ERROR
        return EXIT_VALIDATION_ERROR

    banner(source_used)

    if args.print_config:
        print(json.dumps(client.get_all(), ensure_ascii=False, indent=2))
        return EXIT_OK

    if args.dry_run:
        log_info("Dry-run mode complete. Exiting.")
        return EXIT_OK

    mock_stop = threading.Event()
    mock_thread = None
    if args.mock_remote:
        mock_url = args.remote or "http://127.0.0.1:8765/api/config"
        parsed = urlparse(mock_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8765
        mock_thread = threading.Thread(target=_run_mock_server, args=(host, port, mock_stop), daemon=True)
        mock_thread.start()
        time.sleep(0.2)
        ok, err = client.load_from_remote(save_history=True)
        if ok:
            log_info(f"Refreshed config from local mock server, version={client.version()}")
        elif err:
            log_warn(f"Failed to fetch from mock server: {err}")

    if args.watch:
        client.start_watch(allow_push=args.allow_push)

    stop_event = threading.Event()
    def _sigint_handler(signum, frame):
        log_info("Received shutdown signal, stopping...")
        stop_event.set()
    try:
        signal.signal(signal.SIGINT, _sigint_handler)
        signal.signal(signal.SIGTERM, _sigint_handler)
    except (ValueError, OSError):
        pass

    try:
        while not stop_event.is_set():
            time.sleep(1.0)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        client.stop_watch()
        if mock_thread is not None:
            mock_stop.set()
            mock_thread.join(timeout=2.0)
        log_info("Goodbye.")
    return EXIT_OK


def cmd_set(args) -> int:
    if args.require_key:
        require_crypto_key()

    cfg, err = load_cache()
    if cfg is None:
        if err:
            log_warn(f"Cache load issue: {err}")
        cfg = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        }

    client = ConfigClient(remote_url=args.remote, dry_run=False)
    ok, cerr = client.load_from_cache()
    if not ok:
        client._apply_config(cfg, "cache")

    parsed_value: any
    if args.encrypt:
        key = require_crypto_key()
        enc = configclient.aes_gcm_encrypt(args.value, key)
        if not enc:
            log_error("Encryption failed, value not set")
            return EXIT_IO_ERROR
        parsed_value = enc
    else:
        lower = args.value.lower()
        if lower == "null":
            parsed_value = None
        elif lower == "true":
            parsed_value = True
        elif lower == "false":
            parsed_value = False
        else:
            try:
                if "." in args.value or "e" in args.value.lower():
                    parsed_value = float(args.value)
                else:
                    parsed_value = int(args.value)
            except ValueError:
                parsed_value = args.value

    try:
        client.set(args.key, parsed_value)
    except ValueError as e:
        log_error(str(e))
        return EXIT_ARG_ERROR
    except Exception as e:
        log_error(f"Failed to set key: {e}")
        return EXIT_ARG_ERROR

    all_cfg = client.get_all()
    ok, errs = validate_config(all_cfg)
    if not ok:
        for e in errs:
            log_warn(f"Validation warning after set: {e}")

    ok, e = save_cache(all_cfg)
    if not ok:
        log_error(f"Failed to save cache: {e}")
        return EXIT_IO_ERROR

    save_history(all_cfg)

    log_info(f"Set {args.key} = {parsed_value!r} (version bumped to {client.version()})")

    if args.remote and args.push:
        log_info(f"Pushing updated config to remote {args.remote}")
        ok, perr = push_remote(args.remote, all_cfg)
        if ok:
            log_info("Pushed successfully")
        else:
            log_warn(f"Push failed (will be retried by watch mode): {perr}")
            return EXIT_OK
    return EXIT_OK


def cmd_get(args) -> int:
    if args.require_key:
        require_crypto_key()

    cfg, err = load_cache()
    if cfg is None:
        if err:
            log_error(f"Cannot load config: {err}")
            return EXIT_IO_ERROR
        log_error("No cached configuration found. Run 'configctl run' first.")
        return EXIT_VALIDATION_ERROR

    client = ConfigClient(remote_url=None, dry_run=False)
    client._apply_config(cfg, "cache")

    val = client.get(args.key, decrypt=args.decrypt)
    if val is None:
        log_warn(f"Key not found or decryption failed: {args.key}")
        return EXIT_OK
    if isinstance(val, (dict, list)):
        print(json.dumps(val, ensure_ascii=False, indent=2))
    else:
        print(val)
    return EXIT_OK


def cmd_rollback(args) -> int:
    if args.require_key:
        require_crypto_key()

    versions = list_history_versions()
    if not versions:
        log_error("No history versions found locally. Nothing to roll back.")
        return EXIT_VALIDATION_ERROR

    try:
        target = int(args.to)
    except (ValueError, TypeError):
        log_error(f"Invalid version number: {args.to!r}")
        log_error(f"Available versions (newest first): {', '.join(str(v) for v in versions)}")
        return EXIT_ARG_ERROR

    if target not in versions:
        log_error(f"Version {target} not found in history.")
        log_error(f"Available versions (newest first): {', '.join(str(v) for v in versions)}")
        return EXIT_ARG_ERROR

    target_cfg, err = load_history(target)
    if target_cfg is None:
        log_error(f"Failed to load history version {target}: {err}")
        return EXIT_IO_ERROR

    ok, verrs = validate_config(target_cfg)
    if not ok:
        for e in verrs:
            log_warn(f"Rollback target validation warning: {e}")

    if args.dry_run:
        log_info(f"[dry-run] Would roll back to version {target}")
        log_info(f"Target updated_at: {target_cfg.get('updated_at')}")
        cur_cfg, cerr = load_cache()
        if cur_cfg is not None:
            log_info(f"Current version: {cur_cfg.get('version')}, updated_at: {cur_cfg.get('updated_at')}")
        else:
            log_info("No current cache, would create new.")
        print(json.dumps(target_cfg, ensure_ascii=False, indent=2))
        log_info("[dry-run] No files were modified.")
        return EXIT_OK

    log_info(f"About to roll back to version {target}")
    log_info(f"Target updated_at: {target_cfg.get('updated_at')}")

    cur_cfg, cerr = load_cache()
    if cur_cfg is not None:
        log_info(f"Current version: {cur_cfg.get('version')}, updated_at: {cur_cfg.get('updated_at')}")
    else:
        log_info("No current cache, will create new.")

    if not args.yes:
        try:
            answer = input("Are you sure you want to roll back? [y/N] ").strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("y", "yes"):
            log_info("Rollback cancelled by user.")
            return EXIT_OK

    client = ConfigClient(remote_url=args.remote, dry_run=False)
    client._apply_config(target_cfg, f"rollback:{target}")

    new_cfg = client.get_all()
    cur_v = new_cfg.get("version")
    max_v = versions[0] if versions else 0
    if isinstance(cur_v, int) and not isinstance(cur_v, bool):
        base = max(max_v, cur_v)
        new_cfg["version"] = base + 1
    new_cfg["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    client._apply_config(new_cfg, f"rollback:{target}")

    ok, e = save_cache(new_cfg)
    if not ok:
        log_error(f"Failed to save cache after rollback: {e}")
        return EXIT_IO_ERROR
    save_history(new_cfg)
    log_info(f"Rolled back to version {target}, new local version is {new_cfg.get('version')}")

    if args.remote and args.push:
        log_info(f"Pushing rolled-back config to remote {args.remote}")
        ok, perr = push_remote(args.remote, new_cfg)
        if ok:
            log_info("Pushed rolled-back config successfully")
        else:
            log_warn(f"Push failed: {perr}")
            log_warn("You can retry with: configctl run --watch --allow-push --remote <url>")
            return EXIT_OK
    return EXIT_OK


def cmd_list_versions(_args) -> int:
    versions = list_history_versions()
    if not versions:
        log_info("No history versions found locally.")
        return EXIT_OK
    print(f"Found {len(versions)} history version(s):")
    for v in versions:
        cfg, _ = load_history(v)
        updated = cfg.get("updated_at", "?") if cfg else "?"
        print(f"  version={v:>5}  updated_at={updated}")
    return EXIT_OK


def cmd_encrypt(args) -> int:
    key = require_crypto_key()
    enc = configclient.aes_gcm_encrypt(args.plaintext, key)
    if not enc:
        log_error("Encryption failed")
        return EXIT_IO_ERROR
    print(enc)
    return EXIT_OK


def cmd_decrypt(args) -> int:
    require_crypto_key()
    pt = configclient.aes_gcm_decrypt(args.ciphertext)
    if pt is None:
        log_error("Decryption failed")
        return EXIT_IO_ERROR
    print(pt)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="configctl",
        description="Lightweight configuration center CLI. Loads JSON config from a remote HTTP endpoint, "
                    "caches locally, supports watch mode, rollback, and AES-256-GCM encrypted fields.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  configctl run --remote http://config.internal/api/config --watch
  configctl run --mock-remote --print-config
  configctl set db.host 10.0.0.1 --remote http://config.internal/api/config --push
  configctl set api.secret 's3cret!' --encrypt
  configctl get db.host
  configctl get api.secret --decrypt
  configctl rollback --to 3 --remote http://config.internal/api/config --push
  configctl list-versions
  configctl encrypt "my plaintext"
""",
    )
    parser.add_argument("--version", action="version", version=f"configctl {__version__}")
    parser.add_argument("--no-require-key", dest="require_key", action="store_false", default=True,
                        help="Do not require CONFIG_KEY env var on startup (for testing only)")

    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    p_run = sub.add_parser("run", help="Load config and keep running (optional watch mode and mock server)")
    p_run.add_argument("--remote", "-r", default=None, help="Remote HTTP endpoint URL (GET returns JSON config, PUT accepts update)")
    p_run.add_argument("--watch", "-w", action="store_true", help="Enable watch mode: poll remote every 30s for updates")
    p_run.add_argument("--allow-push", action="store_true", help="In watch mode, push local modifications (via set) back to remote")
    p_run.add_argument("--dry-run", action="store_true", help="Only print what would be loaded, do not modify state, then exit")
    p_run.add_argument("--print-config", action="store_true", help="Print loaded config to stdout and exit (useful for shell scripts)")
    p_run.add_argument("--mock-remote", action="store_true", help="Start a local mock HTTP server returning sample config (for testing)")
    p_run.set_defaults(func=cmd_run)

    p_set = sub.add_parser("set", help="Set a config key locally (bump version, update cache)")
    p_set.add_argument("key", help="Dot-separated key path, e.g. db.host")
    p_set.add_argument("value", help="New value (auto-parsed as number/boolean/null, otherwise string)")
    p_set.add_argument("--encrypt", action="store_true", help="Encrypt value with AES-256-GCM before storing (requires CONFIG_KEY)")
    p_set.add_argument("--remote", "-r", default=None, help="Remote URL; if set together with --push, push immediately")
    p_set.add_argument("--push", action="store_true", help="Push the change to remote immediately (requires --remote)")
    p_set.set_defaults(func=cmd_set)

    p_get = sub.add_parser("get", help="Get a config value from local cache")
    p_get.add_argument("key", help="Dot-separated key path")
    p_get.add_argument("--decrypt", action="store_true", help="If value is encrypted with enc:// prefix, decrypt it (requires CONFIG_KEY)")
    p_get.set_defaults(func=cmd_get)

    p_rb = sub.add_parser("rollback", help="Roll back to a previous version from local history")
    p_rb.add_argument("--to", required=True, help="Target version number (integer)")
    p_rb.add_argument("--yes", "-y", action="store_true", help="Skip interactive confirmation")
    p_rb.add_argument("--dry-run", action="store_true", help="Print the target config but do not apply")
    p_rb.add_argument("--remote", "-r", default=None, help="Remote URL; if set together with --push, push rolled-back version")
    p_rb.add_argument("--push", action="store_true", help="Push rolled-back config to remote immediately (requires --remote)")
    p_rb.set_defaults(func=cmd_rollback)

    p_lv = sub.add_parser("list-versions", help="List locally available history versions")
    p_lv.set_defaults(func=cmd_list_versions)

    p_enc = sub.add_parser("encrypt", help="Encrypt a plaintext string and print the enc://v1:... string (requires CONFIG_KEY)")
    p_enc.add_argument("plaintext", help="Plaintext to encrypt")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt an enc://v1:... string and print plaintext (requires CONFIG_KEY)")
    p_dec.add_argument("ciphertext", help="Ciphertext starting with enc://v1:")
    p_dec.set_defaults(func=cmd_decrypt)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        code = int(e.code) if isinstance(e.code, int) else 0
        if code != 0:
            return EXIT_ARG_ERROR
        return code

    if not hasattr(args, "func"):
        parser.print_help(sys.stderr)
        return EXIT_ARG_ERROR

    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        log_info("Interrupted by user")
        return EXIT_OK
    except SystemExit:
        raise
    except Exception as e:
        log_error(f"Unhandled error: {e.__class__.__name__}: {e}")
        return EXIT_IO_ERROR


if __name__ == "__main__":
    sys.exit(main())
