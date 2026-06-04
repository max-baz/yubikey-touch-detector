#!/usr/bin/env python3
"""yubikey-gpg-notify — show *which process* is asking for a YubiKey touch.

This is a standalone plugin for max-baz/yubikey-touch-detector.  It does not
modify the detector; instead it listens on the Unix socket the detector already
exposes ($XDG_RUNTIME_DIR/yubikey-touch-detector.socket) and reacts to the
documented 5-byte wire messages (GPG_1, GPG_0, ...).

When a GPG touch starts (GPG_1), the calling process is still blocked waiting
for your touch, so its connection to gpg-agent is live.  We trace that
connection with `ss -xpn` to find the caller's PID, read /proc/<pid>/cmdline,
and surface it via `notify-send`.

This approach only works for operations that go through gpg-agent (GPG signing
/ decryption, and SSH when ssh-agent is provided by gpg-agent).  FIDO2/U2F and
PIV do not go through gpg-agent and cannot be resolved this way.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("yubikey-gpg-notify")

# Wire protocol: the detector writes fixed 5-byte messages with no delimiter.
MESSAGE_LEN = 5
GPG_ON = "GPG_1"
GPG_OFF = "GPG_0"

# Background daemons that stay permanently connected to gpg-agent and must never
# be reported as the triggering process.  This includes the detector itself,
# which keeps an Assuan context open for its LEARN probe.  Note that ss reports
# the kernel `comm` name, truncated to 15 chars (e.g. "yubikey-touch-d"), so
# long names here are only matched against the /proc/<pid>/cmdline basename.
EXCLUDED_PROCS = frozenset({"gpg-agent", "scdaemon", "yubikey-touch-detector"})

# How long the "YubiKey was in use" banner lingers after the operation finishes.
POST_TOUCH_MS = 5000


@dataclass
class SocketInfo:
    """One Unix-socket endpoint parsed from a line of `ss -xpn` output."""

    state: str
    local_addr: str  # local socket path, or "" when ss prints "*"
    local_ino: int
    peer_ino: int
    pid: int = 0  # owning process PID, 0 if unknown
    proc_name: str = ""  # owning process name, "" if unknown


# --- ss users-field extraction -------------------------------------------

def extract_ss_pid(users: str) -> int:
    """Extract the first pid=NNN value from an ss users field, or 0."""
    marker = "pid="
    idx = users.find(marker)
    if idx < 0:
        return 0
    rest = users[idx + len(marker):]
    end = len(rest)
    for i, ch in enumerate(rest):
        if ch in ",)":
            end = i
            break
    try:
        return int(rest[:end])
    except ValueError:
        return 0


def extract_ss_name(users: str) -> str:
    """Extract the first process name from an ss users field, or ""."""
    marker = 'users:(("'
    start = users.find(marker)
    if start < 0:
        return ""
    rest = users[start + len(marker):]
    end = rest.find('"')
    if end < 0:
        return ""
    return rest[:end]


# --- ss line / output parsing ---------------------------------------------

def parse_ss_line(line: str) -> SocketInfo | None:
    """Parse one `ss -xpn --no-header` line into a SocketInfo, or None.

    ss prints (whitespace-separated):
        <type> <state> <recv-q> <send-q> <local-addr> <local-ino> <peer-addr> <peer-ino> [users:(...)]
    """
    fields = line.split()
    if len(fields) < 8:
        return None
    try:
        local_ino = int(fields[5])
        peer_ino = int(fields[7])
    except ValueError:
        return None
    if local_ino == 0:
        return None

    local_addr = "" if fields[4] == "*" else fields[4]
    sock = SocketInfo(
        state=fields[1],
        local_addr=local_addr,
        local_ino=local_ino,
        peer_ino=peer_ino,
    )
    for f in fields[8:]:
        if f.startswith("users:"):
            sock.proc_name = extract_ss_name(f)
            sock.pid = extract_ss_pid(f)
            break
    return sock


def parse_ss_output(text: str) -> list[SocketInfo]:
    """Parse full `ss -xpn` output, skipping unparseable lines."""
    out: list[SocketInfo] = []
    for line in text.splitlines():
        sock = parse_ss_line(line)
        if sock is not None:
            out.append(sock)
    return out


# --- /proc and gpgconf helpers --------------------------------------------

def read_proc_cmdline(pid: int) -> str:
    """Return /proc/<pid>/cmdline with NUL separators turned into spaces."""
    if pid <= 0:
        return ""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
    except OSError:
        return ""
    return " ".join(p for p in raw.decode("utf-8", "replace").split("\x00") if p)


def gpg_agent_socket_paths() -> set[str]:
    """Query gpgconf for every Unix socket gpg-agent listens on."""
    paths: set[str] = set()
    for kind in ("agent-socket", "agent-ssh-socket", "agent-extra-socket", "agent-browser-socket"):
        try:
            out = subprocess.run(
                ["gpgconf", "--list-dirs", kind],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            continue
        if out:
            paths.add(out)
    return paths


def run_ss() -> str:
    """Run `ss -xpn --no-header` and return its stdout (empty on failure)."""
    try:
        return subprocess.run(
            ["ss", "-xpn", "--no-header"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        log.debug("ss failed: %s", exc)
        return ""


# --- context resolution ----------------------------------------------------

def find_gpg_context(
    sockets: list[SocketInfo],
    agent_paths: set[str],
    read_cmdline: Callable[[int], str] = read_proc_cmdline,
) -> list[str]:
    """Return command lines of processes currently connected to gpg-agent.

    On the server side of each accepted connection, ss shows the socket file
    path as the local address even though the accepted socket is anonymous; the
    client side shows local="*" but carries the readable users field.  We pair
    the two via the kernel peer-inode link.
    """
    if not agent_paths:
        return []

    by_local_ino: dict[int, SocketInfo] = {s.local_ino: s for s in sockets}

    results: list[str] = []
    seen: set[int] = set()
    for s in sockets:
        if s.state != "ESTAB" or s.local_addr not in agent_paths:
            continue
        client = by_local_ino.get(s.peer_ino)
        if client is None or client.pid == 0:
            continue
        if client.pid in seen:
            continue
        seen.add(client.pid)
        if client.proc_name in EXCLUDED_PROCS:
            continue
        cmdline = read_cmdline(client.pid)
        if not cmdline:
            continue
        if os.path.basename(cmdline.split()[0]) in EXCLUDED_PROCS:
            continue
        results.append(cmdline)
    return results


def resolve_gpg_context() -> str:
    """Live one-shot context resolution: returns a newline-joined cmdline list."""
    return "\n".join(find_gpg_context(parse_ss_output(run_ss()), gpg_agent_socket_paths()))


# --- wire-protocol message framing ----------------------------------------

def split_messages(buf: bytes) -> tuple[list[str], bytes]:
    """Split a byte buffer into complete 5-byte messages plus any remainder."""
    msgs: list[str] = []
    n = len(buf) - (len(buf) % MESSAGE_LEN)
    for i in range(0, n, MESSAGE_LEN):
        msgs.append(buf[i:i + MESSAGE_LEN].decode("ascii", "replace"))
    return msgs, buf[n:]


# --- notification handling -------------------------------------------------

class Notifier:
    """Manages a single replaceable desktop notification via notify-send."""

    def __init__(self, send: Callable[[list[str]], str] | None = None) -> None:
        self._send = send or self._notify_send
        self._replace_id = "0"
        self._active = 0
        self._last_context = ""

    def _notify_send(self, args: list[str]) -> str:
        try:
            out = subprocess.run(
                ["notify-send", "-p", "-a", "yubikey-touch-detector", *args],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            return out or "0"
        except (OSError, subprocess.CalledProcessError) as exc:
            log.error("notify-send failed: %s", exc)
            return "0"

    def _show(self, summary: str, body: str, expire_ms: int) -> None:
        args = ["-r", self._replace_id, "-t", str(expire_ms)]
        if body:
            args += [summary, body]
        else:
            args += [summary]
        self._replace_id = self._send(args)

    def touch_started(self, context: str) -> None:
        self._active += 1
        if context:
            self._last_context = context
        self._show("YubiKey is waiting for a touch", self._last_context, 0)

    def touch_finished(self) -> None:
        if self._active > 0:
            self._active -= 1
        if self._active == 0:
            self._show("YubiKey was in use", self._last_context, POST_TOUCH_MS)
            self._last_context = ""


# --- socket loop -----------------------------------------------------------

def socket_path() -> str:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        raise SystemExit("XDG_RUNTIME_DIR is not set; cannot locate the detector socket")
    return os.path.join(runtime, "yubikey-touch-detector.socket")


def handle_message(msg: str, notifier: Notifier) -> None:
    if msg == GPG_ON:
        context = resolve_gpg_context()
        log.debug("GPG touch started, context=%r", context)
        notifier.touch_started(context)
    elif msg == GPG_OFF:
        log.debug("GPG touch finished")
        notifier.touch_finished()
    else:
        log.debug("ignoring message %r (only GPG context is supported)", msg)


def serve(path: str, notifier: Notifier) -> None:
    """Connect to the detector socket and dispatch messages until it closes."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    log.info("connected to %s", path)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                log.info("detector closed the connection")
                return
            buf += chunk
            msgs, buf = split_messages(buf)
            for msg in msgs:
                handle_message(msg, notifier)
    finally:
        sock.close()


def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    path = socket_path()
    notifier = Notifier()
    while True:
        try:
            serve(path, notifier)
        except (FileNotFoundError, ConnectionRefusedError):
            log.warning("detector socket not available, retrying in 5s")
        except OSError as exc:
            log.warning("socket error: %s, retrying in 5s", exc)
        time.sleep(5)


if __name__ == "__main__":
    sys.exit(main())
