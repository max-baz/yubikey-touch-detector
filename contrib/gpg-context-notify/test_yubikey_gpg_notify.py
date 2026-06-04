"""Unit tests for the yubikey-gpg-notify plugin.

These cover the pure parsing / context-resolution logic.  The socket loop and
notify-send invocation are intentionally thin and exercised manually.
"""

import os
import socket
import threading

import yubikey_gpg_notify as m


# --- ss users-field extraction -------------------------------------------

def test_extract_ss_pid():
    assert m.extract_ss_pid('users:(("git",pid=600,fd=5))') == 600
    assert m.extract_ss_pid('users:(("gpg-agent",pid=42,fd=10),("x",pid=7,fd=1))') == 42


def test_extract_ss_pid_missing():
    assert m.extract_ss_pid("") == 0
    assert m.extract_ss_pid("users:no-pid-here") == 0


def test_extract_ss_name():
    assert m.extract_ss_name('users:(("git",pid=600,fd=5))') == "git"
    assert m.extract_ss_name('users:(("gpg-agent",pid=42,fd=10))') == "gpg-agent"


def test_extract_ss_name_missing():
    assert m.extract_ss_name("") == ""
    assert m.extract_ss_name("garbage") == ""


# --- ss line / output parsing ---------------------------------------------

def test_parse_ss_line_with_path_and_users():
    line = (
        'u_str ESTAB 0 0 /run/user/1000/gnupg/S.gpg-agent 111 * 112 '
        'users:(("gpg-agent",pid=500,fd=10))'
    )
    sock = m.parse_ss_line(line)
    assert sock is not None
    assert sock.state == "ESTAB"
    assert sock.local_addr == "/run/user/1000/gnupg/S.gpg-agent"
    assert sock.local_ino == 111
    assert sock.peer_ino == 112
    assert sock.pid == 500
    assert sock.proc_name == "gpg-agent"


def test_parse_ss_line_star_addr_becomes_empty():
    line = 'u_str ESTAB 0 0 * 112 * 111 users:(("git",pid=600,fd=5))'
    sock = m.parse_ss_line(line)
    assert sock is not None
    assert sock.local_addr == ""
    assert sock.local_ino == 112
    assert sock.peer_ino == 111
    assert sock.pid == 600


def test_parse_ss_line_rejects_short_and_zero_inode():
    assert m.parse_ss_line("u_str ESTAB 0 0 *") is None
    assert m.parse_ss_line("") is None
    # local inode 0 is meaningless and must be dropped
    assert m.parse_ss_line("u_str LISTEN 0 0 /x 0 * 0") is None


def test_parse_ss_output_skips_garbage_lines():
    text = (
        'u_str ESTAB 0 0 /run/user/1000/gnupg/S.gpg-agent 111 * 112 users:(("gpg-agent",pid=500,fd=10))\n'
        "this is not a socket line\n"
        '\n'
        'u_str ESTAB 0 0 * 112 * 111 users:(("git",pid=600,fd=5))\n'
    )
    socks = m.parse_ss_output(text)
    assert len(socks) == 2
    assert {s.local_ino for s in socks} == {111, 112}


# --- find_gpg_context ------------------------------------------------------

def _cmdline_lookup(table):
    return lambda pid: table.get(pid, "")


def test_find_gpg_context_resolves_caller():
    socks = m.parse_ss_output(
        'u_str ESTAB 0 0 /run/user/1000/gnupg/S.gpg-agent 111 * 112 users:(("gpg-agent",pid=500,fd=10))\n'
        'u_str ESTAB 0 0 * 112 * 111 users:(("git",pid=600,fd=5))\n'
    )
    agent_paths = {"/run/user/1000/gnupg/S.gpg-agent"}
    result = m.find_gpg_context(
        socks, agent_paths, read_cmdline=_cmdline_lookup({600: "git commit -S -m wip"})
    )
    assert result == ["git commit -S -m wip"]


def test_find_gpg_context_excludes_background_daemons():
    # scdaemon is permanently connected to gpg-agent and must be filtered out.
    socks = m.parse_ss_output(
        'u_str ESTAB 0 0 /run/user/1000/gnupg/S.gpg-agent 111 * 112 users:(("gpg-agent",pid=500,fd=10))\n'
        'u_str ESTAB 0 0 * 112 * 111 users:(("scdaemon",pid=700,fd=5))\n'
    )
    agent_paths = {"/run/user/1000/gnupg/S.gpg-agent"}
    result = m.find_gpg_context(
        socks, agent_paths, read_cmdline=_cmdline_lookup({700: "scdaemon --multi-server"})
    )
    assert result == []


def test_find_gpg_context_excludes_detector_by_cmdline_basename():
    # ss reports the truncated `comm` ("yubikey-touch-d"), which does NOT match
    # the exclusion list, so exclusion must fall through to the cmdline basename.
    socks = m.parse_ss_output(
        'u_str ESTAB 0 0 /run/user/1000/gnupg/S.gpg-agent 111 * 112 users:(("gpg-agent",pid=500,fd=10))\n'
        'u_str ESTAB 0 0 * 112 * 111 users:(("yubikey-touch-d",pid=800,fd=5))\n'
    )
    agent_paths = {"/run/user/1000/gnupg/S.gpg-agent"}
    result = m.find_gpg_context(
        socks, agent_paths,
        read_cmdline=_cmdline_lookup({800: "/home/me/.local/bin/yubikey-touch-detector"}),
    )
    assert result == []


def test_find_gpg_context_dedups_pid_across_sockets():
    socks = m.parse_ss_output(
        'u_str ESTAB 0 0 /run/user/1000/gnupg/S.gpg-agent 111 * 112 users:(("gpg-agent",pid=500,fd=10))\n'
        'u_str ESTAB 0 0 /run/user/1000/gnupg/S.gpg-agent 113 * 114 users:(("gpg-agent",pid=500,fd=11))\n'
        'u_str ESTAB 0 0 * 112 * 111 users:(("ssh",pid=600,fd=5))\n'
        'u_str ESTAB 0 0 * 114 * 113 users:(("ssh",pid=600,fd=6))\n'
    )
    agent_paths = {"/run/user/1000/gnupg/S.gpg-agent"}
    result = m.find_gpg_context(
        socks, agent_paths, read_cmdline=_cmdline_lookup({600: "ssh myhost"})
    )
    assert result == ["ssh myhost"]


def test_find_gpg_context_empty_when_no_agent_paths():
    socks = m.parse_ss_output(
        'u_str ESTAB 0 0 * 112 * 111 users:(("git",pid=600,fd=5))\n'
    )
    assert m.find_gpg_context(socks, set(), read_cmdline=_cmdline_lookup({600: "git"})) == []


# --- wire-protocol message framing ----------------------------------------

def test_split_messages_exact_chunks():
    msgs, rest = m.split_messages(b"GPG_1GPG_0")
    assert msgs == ["GPG_1", "GPG_0"]
    assert rest == b""


def test_split_messages_keeps_partial_remainder():
    msgs, rest = m.split_messages(b"GPG_1GP")
    assert msgs == ["GPG_1"]
    assert rest == b"GP"


def test_split_messages_empty():
    assert m.split_messages(b"") == ([], b"")


# --- Notifier state machine -----------------------------------------------

class _FakeSend:
    def __init__(self):
        self.calls = []

    def __call__(self, args):
        self.calls.append(args)
        return "42"  # pretend notify-send returned this id


def test_notifier_shows_context_then_replaces_with_banner():
    send = _FakeSend()
    n = m.Notifier(send=send)

    n.touch_started("git commit -S")
    n.touch_finished()

    assert len(send.calls) == 2
    start, end = send.calls
    # First notification: persistent (expire 0), carries the context as body.
    assert "YubiKey is waiting for a touch" in start
    assert "git commit -S" in start
    assert start[start.index("-t") + 1] == "0"
    # Second: the post-touch banner with a finite expiry, reusing the id (-r 42).
    assert "YubiKey was in use" in end
    assert end[end.index("-r") + 1] == "42"
    assert end[end.index("-t") + 1] == str(m.POST_TOUCH_MS)


def test_notifier_banner_only_when_all_waits_finished():
    send = _FakeSend()
    n = m.Notifier(send=send)

    n.touch_started("op A")
    n.touch_started("op B")
    n.touch_finished()  # one still active → no banner yet
    assert all("was in use" not in c for c in [" ".join(x) for x in send.calls])

    n.touch_finished()  # now idle → banner
    assert any("YubiKey was in use" in c for c in send.calls[-1])


def test_handle_message_ignores_non_gpg(monkeypatch):
    send = _FakeSend()
    n = m.Notifier(send=send)
    m.handle_message("U2F_1", n)
    m.handle_message("MAC_0", n)
    assert send.calls == []


# --- end-to-end socket loop ------------------------------------------------

def test_serve_reads_framed_messages_from_socket(tmp_path, monkeypatch):
    # Resolve context without touching the real system.
    monkeypatch.setattr(m, "resolve_gpg_context", lambda: "ssh myhost")

    path = str(tmp_path / "ytd.socket")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)

    def feed():
        conn, _ = srv.accept()
        # Two GPG events split across recv boundaries, plus an ignored U2F one.
        conn.sendall(b"GPG_1U2F_1GP")
        conn.sendall(b"G_0")
        conn.close()

    t = threading.Thread(target=feed)
    t.start()

    send = _FakeSend()
    notifier = m.Notifier(send=send)
    m.serve(path, notifier)  # returns when the server closes the connection
    t.join()
    srv.close()

    summaries = [" ".join(c) for c in send.calls]
    assert any("waiting for a touch" in s and "ssh myhost" in s for s in summaries)
    assert any("was in use" in s for s in summaries)
