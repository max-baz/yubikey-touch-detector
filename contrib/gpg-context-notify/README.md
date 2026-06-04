# yubikey-gpg-notify

A standalone notification plugin for
[yubikey-touch-detector](https://github.com/max-baz/yubikey-touch-detector)
that tells you **which process** is asking for a YubiKey touch — e.g.

```
YubiKey is waiting for a touch
git commit -S -m "release v1.2.3"
```

## Why a plugin (and not a patch)

The detector already exposes a Unix socket
(`$XDG_RUNTIME_DIR/yubikey-touch-detector.socket`) that broadcasts fixed 5-byte
messages whenever a touch is requested or completed (`GPG_1` / `GPG_0`, etc).
This is the same socket the
[`waybar-yubikey`](https://github.com/max-baz/dotfiles/blob/main/modules/linux/bin/waybar-yubikey)
example listens on.

This plugin listens on that socket and, when a **GPG** touch starts, traces the
caller's connection to `gpg-agent` to identify it. Because it lives entirely on
top of the published socket protocol, it needs **no changes to the detector**
and keeps working across detector upgrades.

See [the PR discussion](https://github.com/max-baz/yubikey-touch-detector/pull/82)
for the design rationale.

## How it works

When the detector emits `GPG_1`, the process that triggered the request is still
blocked waiting for your touch, so its connection to `gpg-agent` is live. The
plugin then:

1. Runs `ss -xpn` to list all connected Unix-socket pairs (keyed by kernel
   inode).
2. Asks `gpgconf --list-dirs` for the socket paths `gpg-agent` listens on.
3. Finds `gpg-agent`'s accepted (`ESTAB`) sockets, follows the kernel
   peer-inode link to the client socket, and reads its owning PID.
4. Reads `/proc/<pid>/cmdline` for the full command line and shows it via
   `notify-send`.

`gpg-agent`, `scdaemon` and the detector itself are filtered out as background
connections.

## Scope and limitations

- **Only GPG-agent-backed operations** can be resolved: GPG signing/decryption,
  and SSH when `ssh-agent` is provided by `gpg-agent`. FIDO2/U2F (browser) and
  PIV do **not** go through `gpg-agent` and cannot be identified this way.
- With SSH **agent forwarding**, the resolved caller is the local `ssh` client,
  not the remote command — the remote side is not visible locally.
- Identification is best-effort: it reports the process holding the connection,
  not a cryptographic proof of what is being signed.

## Requirements

- Python 3.9+
- `ss` (iproute2), `gpgconf` (gnupg), `notify-send` (libnotify ≥ 0.7.9 for
  `-p`/`-r`)
- A running `yubikey-touch-detector` with its Unix socket enabled (the default)

## Usage

Run it directly:

```sh
./yubikey_gpg_notify.py
```

Set `DEBUG=1` for verbose logging. If you also run the detector's built-in
libnotify notifier you will get duplicate "waiting for a touch" popups — disable
one of them.

### As a systemd user service

Copy the script somewhere stable and install the unit:

```sh
install -Dm755 yubikey_gpg_notify.py ~/.local/bin/yubikey-gpg-notify
install -Dm644 yubikey-gpg-notify.service ~/.config/systemd/user/yubikey-gpg-notify.service
systemctl --user daemon-reload
systemctl --user enable --now yubikey-gpg-notify.service
```

## Tests

```sh
python3 -m pytest
```
