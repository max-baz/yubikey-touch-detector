# Process context in notifications

When YubiKey touch detector fires a notification, it attempts to identify *which
process* triggered the touch request and includes that information in the
notification body.  This helps you verify that a legitimate operation is
requesting the touch, rather than a rogue program.

## How it works per operation type

### GPG / SSH agent

GPG operations go through `gpg-agent`, which accepts connections over a Unix
domain socket.  To find the caller, the detector:

1. Runs `ss -xpn` to obtain a table of all connected Unix socket pairs, indexed
   by their kernel-assigned inode numbers.
2. Scans `/proc` to find the `gpg-agent` process(es) and records the inode of
   every socket file descriptor they hold open.
3. For each of those inodes, follows the peer-inode link from step 1 to find
   the *other* process that is connected to `gpg-agent` at this moment.
4. Reads `/proc/<pid>/cmdline` for that process to obtain its full command line.

Background daemons that are permanently connected to `gpg-agent` (currently
`gpg-agent` itself and `scdaemon`) are filtered out.  All remaining callers are
reported, one per line, in the notification body.

**Example notification body:**

```
git commit -S -m "my commit message"
```

or, if multiple callers are active simultaneously:

```
git commit -S -m "sign release"
ansible-playbook site.yml
```

#### SSH agent forwarding

When the SSH detector intercepts traffic destined for `gpg-agent` acting as an
SSH agent, it identifies the peer process on the intercepted socket connection
directly via `SO_PEERCRED` (a single syscall that returns the connecting
process's PID without any `/proc` scanning).

### U2F / FIDO2 and PIV / HMAC-SHA1

These operations are triggered by direct device access rather than through a
socket-based agent, so no process-identification is performed.  The notification
body will be empty for these cases.

## Notification behaviour

| State | Summary | Body | Timeout |
|---|---|---|---|
| Waiting for touch | "YubiKey is waiting for a touch" | Caller command line(s) | Persistent — stays until touched |
| Operation just completed | "YubiKey was in use" | Caller command line(s) | Auto-dismisses after 5 seconds |

The notification deliberately stays visible after the touch is accepted so you
have time to read which process triggered the operation.

## Limitations and caveats

- The `/proc` scan and `ss` invocation happen at the moment the GPG file-open
  event is detected, which is slightly *before* the card actually prompts for a
  touch.  In rare race conditions a very short-lived caller may already have
  exited before the scan runs, and no context will be shown.
- Only processes running as the same user (or root) can be inspected via
  `/proc/<pid>/fd`.  Cross-user scenarios (e.g. sudo gpg) may not surface the
  outer caller.
- The command line shown is the full `argv` of the direct caller.  If the
  operation was initiated by a shell script or a wrapper, the intermediate
  process name is shown, not the human who typed the command.
