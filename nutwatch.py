#!/usr/bin/env python3
"""Monitor NUT UPS metrics and execute commands based on YAML-configured thresholds."""

from __future__ import annotations

import argparse
import logging
import os
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    import yaml
    YAML_IMPORT_ERROR = None
except ModuleNotFoundError as exc:
    yaml = None
    YAML_IMPORT_ERROR = exc

LOGGER = logging.getLogger("nutwatch")


OPERATOR_MAP: Dict[str, Callable[[float, float], bool]] = {
    "<": lambda current, target: current < target,
    "<=": lambda current, target: current <= target,
    ">": lambda current, target: current > target,
    ">=": lambda current, target: current >= target,
    "==": lambda current, target: current == target,
    "!=": lambda current, target: current != target,
}

OPERATOR_ALIAS = {
    "lt": "<",
    "lte": "<=",
    "gt": ">",
    "gte": ">=",
    "eq": "==",
    "ne": "!=",
}


class UnknownUpsError(RuntimeError):
    def __init__(self, ups_name: str, available_ups: List[str]) -> None:
        self.ups_name = ups_name
        self.available_ups = available_ups
        available_text = ", ".join(available_ups) if available_ups else "none discovered"
        super().__init__(
            f"NUT server returned ERR UNKNOWN-UPS for '{ups_name}'. Available UPS names: {available_text}"
        )


class NutClient:
    def __init__(
        self,
        host: str,
        port: int,
        timeout_seconds: float,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout_seconds = timeout_seconds
        self.username = username
        self.password = password

    def list_vars(self, ups_name: str) -> Dict[str, str]:
        with socket.create_connection((self.host, self.port), timeout=self.timeout_seconds) as sock:
            sock.settimeout(self.timeout_seconds)
            with sock.makefile("rwb") as sock_file:
                self._authenticate(sock_file)
                self._send_command(sock_file, f"LIST VAR {ups_name}")
                begin_line = self._read_line(sock_file)
                expected_begin = f"BEGIN LIST VAR {ups_name}"
                if begin_line != expected_begin:
                    if begin_line == "ERR UNKNOWN-UPS":
                        raise UnknownUpsError(ups_name=ups_name, available_ups=self._safe_list_ups())
                    if begin_line.startswith("ERR"):
                        raise RuntimeError(f"NUT server error: {begin_line}")
                    raise RuntimeError(f"Unexpected response: {begin_line}")

                values: Dict[str, str] = {}
                while True:
                    line = self._read_line(sock_file)
                    if line.startswith("END LIST VAR"):
                        break
                    if line.startswith("VAR "):
                        parsed = self._parse_var_line(line)
                        if parsed is not None:
                            key, value = parsed
                            values[key] = value
                return values

    def list_ups(self) -> List[str]:
        with socket.create_connection((self.host, self.port), timeout=self.timeout_seconds) as sock:
            sock.settimeout(self.timeout_seconds)
            with sock.makefile("rwb") as sock_file:
                self._authenticate(sock_file)
                self._send_command(sock_file, "LIST UPS")
                begin_line = self._read_line(sock_file)
                if begin_line != "BEGIN LIST UPS":
                    if begin_line.startswith("ERR"):
                        raise RuntimeError(f"NUT server error: {begin_line}")
                    raise RuntimeError(f"Unexpected response: {begin_line}")

                ups_names: List[str] = []
                while True:
                    line = self._read_line(sock_file)
                    if line == "END LIST UPS":
                        break
                    parsed_name = self._parse_ups_line(line)
                    if parsed_name is not None:
                        ups_names.append(parsed_name)
                return ups_names

    def _authenticate(self, sock_file: Any) -> None:
        if not self.username:
            return

        self._send_command(sock_file, f"USERNAME {self.username}")
        username_reply = self._read_line(sock_file)
        if not username_reply.startswith("OK"):
            raise RuntimeError(f"Username authentication failed: {username_reply}")

        if not self.password:
            return

        self._send_command(sock_file, f"PASSWORD {self.password}")
        password_reply = self._read_line(sock_file)
        if not password_reply.startswith("OK"):
            raise RuntimeError(f"Password authentication failed: {password_reply}")

    @staticmethod
    def _send_command(sock_file: Any, command: str) -> None:
        sock_file.write((command + "\n").encode("utf-8"))
        sock_file.flush()

    @staticmethod
    def _read_line(sock_file: Any) -> str:
        raw = sock_file.readline()
        if not raw:
            raise RuntimeError("NUT server closed the connection")
        return raw.decode("utf-8", errors="replace").strip()

    @staticmethod
    def _parse_var_line(line: str) -> Optional[tuple[str, str]]:
        try:
            parts = shlex.split(line)
        except ValueError:
            return None

        if len(parts) < 4 or parts[0] != "VAR":
            return None
        key = parts[2]
        value = " ".join(parts[3:])
        return key, value

    @staticmethod
    def _parse_ups_line(line: str) -> Optional[str]:
        try:
            parts = shlex.split(line)
        except ValueError:
            return None
        if len(parts) < 2 or parts[0] != "UPS":
            return None
        return parts[1]

    def _safe_list_ups(self) -> List[str]:
        try:
            return self.list_ups()
        except Exception as exc:  # pylint: disable=broad-except
            LOGGER.debug("Failed to list available UPS names: %s", exc)
            return []


class RuleState:
    def __init__(self) -> None:
        self.active = False
        self.last_trigger_time = 0.0


class NutWatch:
    def __init__(self, config: Dict[str, Any], dry_run: bool = False) -> None:
        self.config = config
        self.dry_run = dry_run
        self.stop_event = threading.Event()
        self.states: Dict[str, RuleState] = {}

        nut_cfg = config["nut"]
        self.client = NutClient(
            host=str(nut_cfg["host"]),
            port=int(nut_cfg.get("port", 3493)),
            timeout_seconds=float(nut_cfg.get("timeout_seconds", 5)),
            username=nut_cfg.get("username"),
            password=nut_cfg.get("password"),
        )
        self.ups_name = str(nut_cfg["ups_name"])
        self.poll_interval_seconds = float(config.get("poll_interval_seconds", 15))
        self.command_defaults = config.get("command_defaults", {})
        self.rules = self._normalize_rules(config.get("rules", []))

        for rule in self.rules:
            self.states[rule["name"]] = RuleState()

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        LOGGER.info("nutwatch started for UPS '%s' at %s:%s", self.ups_name, self.client.host, self.client.port)
        if self.dry_run:
            LOGGER.info("Dry-run mode enabled: commands will be logged but not executed")

        while not self.stop_event.is_set():
            try:
                self._poll_once()
            except UnknownUpsError as exc:
                LOGGER.error("polling failed: %s", exc)
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.exception("polling failed: %s", exc)

            self.stop_event.wait(self.poll_interval_seconds)

        LOGGER.info("nutwatch stopped")

    def _poll_once(self) -> None:
        vars_map = self.client.list_vars(self.ups_name)
        LOGGER.debug("Fetched %d vars from NUT", len(vars_map))

        for rule in self.rules:
            rule_name = rule["name"]
            var_name = rule["var"]
            raw_value = vars_map.get(var_name)
            if raw_value is None:
                LOGGER.warning("Rule '%s' skipped: var '%s' missing", rule_name, var_name)
                continue

            current_value = self._to_float(raw_value, var_name, rule_name)
            if current_value is None:
                continue

            threshold = float(rule["threshold"])
            operator_symbol = rule["operator"]
            condition_met = OPERATOR_MAP[operator_symbol](current_value, threshold)
            state = self.states[rule_name]
            should_fire = False

            if condition_met:
                if rule["trigger"] == "always":
                    should_fire = True
                elif rule["trigger"] == "on_enter" and not state.active:
                    should_fire = True

            now = time.time()
            cooldown = float(rule["cooldown_seconds"])
            if should_fire and now - state.last_trigger_time < cooldown:
                LOGGER.info("Rule '%s' matched but in cooldown", rule_name)
                should_fire = False

            if should_fire:
                LOGGER.info(
                    "Rule '%s' fired: %s %s %s (current=%.2f)",
                    rule_name,
                    var_name,
                    operator_symbol,
                    threshold,
                    current_value,
                )
                self._run_commands(rule_name, rule["commands"])
                state.last_trigger_time = now

            state.active = condition_met

    def _run_commands(self, rule_name: str, commands: List[Dict[str, Any]]) -> None:
        for idx, cmd_cfg in enumerate(commands, start=1):
            cmd = cmd_cfg["cmd"]
            shell = bool(cmd_cfg.get("shell", self.command_defaults.get("shell", True)))
            timeout_seconds = float(
                cmd_cfg.get("timeout_seconds", self.command_defaults.get("timeout_seconds", 30))
            )
            continue_on_error = bool(cmd_cfg.get("continue_on_error", True))

            env = os.environ.copy()
            env_overrides = cmd_cfg.get("env", {})
            if isinstance(env_overrides, dict):
                env.update({str(k): str(v) for k, v in env_overrides.items()})

            LOGGER.info("Rule '%s' executing command #%d: %s", rule_name, idx, cmd)

            if self.dry_run:
                LOGGER.info("Rule '%s' dry-run command #%d skipped", rule_name, idx)
                continue

            args: Any = cmd
            if not shell and isinstance(cmd, str):
                args = shlex.split(cmd)

            try:
                completed = subprocess.run(  # noqa: S603
                    args,
                    shell=shell,
                    timeout=timeout_seconds,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                LOGGER.error("Rule '%s' command #%d timed out after %.1fs", rule_name, idx, timeout_seconds)
                if not continue_on_error:
                    break
                continue
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.exception("Rule '%s' command #%d failed to start: %s", rule_name, idx, exc)
                if not continue_on_error:
                    break
                continue

            if completed.stdout:
                LOGGER.info("Rule '%s' command #%d stdout: %s", rule_name, idx, completed.stdout.strip())
            if completed.stderr:
                LOGGER.warning("Rule '%s' command #%d stderr: %s", rule_name, idx, completed.stderr.strip())

            if completed.returncode != 0:
                LOGGER.error(
                    "Rule '%s' command #%d exited with code %d",
                    rule_name,
                    idx,
                    completed.returncode,
                )
                if not continue_on_error:
                    break

    @staticmethod
    def _to_float(raw_value: str, var_name: str, rule_name: str) -> Optional[float]:
        try:
            return float(raw_value)
        except ValueError:
            LOGGER.warning(
                "Rule '%s' skipped: var '%s' value '%s' is not numeric",
                rule_name,
                var_name,
                raw_value,
            )
            return None

    @staticmethod
    def _normalize_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        seen_names = set()
        for idx, rule in enumerate(rules, start=1):
            if not isinstance(rule, dict):
                raise ValueError(f"rules[{idx}] must be an object")

            name = str(rule.get("name") or f"rule_{idx}")
            if name in seen_names:
                raise ValueError(f"Duplicate rule name detected: {name}")
            seen_names.add(name)
            operator = str(rule.get("operator", "<="))
            operator = OPERATOR_ALIAS.get(operator, operator)
            if operator not in OPERATOR_MAP:
                raise ValueError(f"rules[{idx}] has invalid operator: {operator}")

            trigger = str(rule.get("trigger", "on_enter"))
            if trigger not in {"on_enter", "always"}:
                raise ValueError(f"rules[{idx}] has invalid trigger: {trigger}")

            threshold = rule.get("threshold")
            if threshold is None:
                raise ValueError(f"rules[{idx}] missing required field: threshold")

            commands = rule.get("commands")
            if not isinstance(commands, list) or not commands:
                raise ValueError(f"rules[{idx}] must define non-empty commands list")

            normalized_commands = []
            for cmd_idx, cmd in enumerate(commands, start=1):
                if isinstance(cmd, str):
                    normalized_commands.append({"cmd": cmd})
                elif isinstance(cmd, dict) and "cmd" in cmd:
                    normalized_commands.append(cmd)
                else:
                    raise ValueError(
                        f"rules[{idx}].commands[{cmd_idx}] must be string or object with cmd field"
                    )

            normalized.append(
                {
                    "name": name,
                    "var": str(rule.get("var", "battery.charge")),
                    "operator": operator,
                    "threshold": float(threshold),
                    "trigger": trigger,
                    "cooldown_seconds": float(rule.get("cooldown_seconds", 0)),
                    "commands": normalized_commands,
                }
            )

        if not normalized:
            raise ValueError("At least one rule must be configured")

        return normalized

    def _handle_signal(self, signum: int, _frame: Any) -> None:
        LOGGER.info("Received signal %d, shutting down", signum)
        self.stop_event.set()


def load_config(config_path: Path) -> Dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required. Install with: pip3 install -r requirements.txt") from YAML_IMPORT_ERROR
    with config_path.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file) or {}
    if not isinstance(config, dict):
        raise ValueError("Config root must be a YAML object")

    if "nut" not in config or not isinstance(config["nut"], dict):
        raise ValueError("Config must include 'nut' object")
    if "ups_name" not in config["nut"]:
        raise ValueError("Config nut section must include 'ups_name'")
    if "host" not in config["nut"]:
        raise ValueError("Config nut section must include 'host'")

    return config


def setup_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor NUT UPS data and execute configured commands")
    parser.add_argument("--config", required=True, help="Path to YAML config file")
    parser.add_argument(
        "--dry",
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Enable dry-run mode (log commands without executing them)",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    config_path = Path(args.config).expanduser()
    config = load_config(config_path)

    setup_logging(str(config.get("log_level", "INFO")))

    watcher = NutWatch(config, dry_run=bool(args.dry_run))
    watcher.run()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
