yubikey-touch-detector(1)

# NAME

yubikey-touch-detector - detect when a YubiKey is waiting for a touch

# SYNOPSIS

*yubikey-touch-detector* [options...]

# OPTIONS

*-libnotify*
	Show desktop notifications using libnotify.

*-no-socket*
	Disable unix socket notifier.

*-stdout*
	Print notifications to stdout.

*-v*
	Enable debug logging.

*-version*
	Print version information and exit.

# DESCRIPTION

*yubikey-touch-detector* detects when a YubiKey is waiting for a touch
configuration. It is designed to be integrated with other UI components to
display a visible indicator.

# ENVIRONMENT

_YUBIKEY_TOUCH_DETECTOR_VERBOSE_
	Equivalent to specifying *-v*.

_YUBIKEY_TOUCH_DETECTOR_LIBNOTIFY_
	Equivalent to specifying *-libnotify*.

_YUBIKEY_TOUCH_DETECTOR_STDOUT_
	Equivalent to specifying *-stdout*.

_YUBIKEY_TOUCH_DETECTOR_NOSOCKET_
	Equivalent to specifying *-no-socket*.

# FILES

_$XDG_RUNTIME_DIR/yubikey-touch-detector.socket_
	The socket exposing events shall be created at this locatoin.

# EVENTS

The following events are emitted over the socket:

_GPG_1_
	When a GPG operation starts waiting for a touch.

_GPG_0_
	When a GPG operation stops waiting for a touch.

_U2F_1_
	When a U2F operation starts waiting for a touch.

_U2F_0_
	When a U2F operation stops waiting for a touch.

_MAC_1_
	When a HMAC operation starts waiting for a touch.

_MAC_0_
	When a HMAC operation stops waiting for a touch.

# SEE ALSO

ykman, pam_u2f(8)

# LICENCE

yubikey-touch-detector is distributed under the ISC licence.
