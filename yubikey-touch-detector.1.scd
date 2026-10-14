yubikey-touch-detector(1)

# NAME

yubikey-touch-detector - detect when a YubiKey is waiting for a touch

# SYNOPSIS

*yubikey-touch-detector* [options...]

# OPTIONS

*-notify*
	Show desktop notifications.

*-notify-title* _title_
	Set the desktop notification title template. Defaults to "YubiKey is waiting for a touch".

*-notify-body* _body_
	Set the desktop notification body template. Defaults to "Touch your YubiKey to continue ({{.Reasons}})." followed by _{{.Details}}_ on a new line.

*-notify-urgency* _urgency_
	Set the desktop notification urgency: low, normal, or critical. Defaults to "normal". Notification daemons typically keep critical notifications on screen until they are dismissed; the app closes its notification as soon as the touch is registered.

*-details-template* _template_
	Go template describing the request that waits for a touch, e.g. the SSH session. Defaults to "SSH to {{.Target}} ({{.Address}})". Available fields: _{{.User}}_, _{{.Host}}_ (as typed), _{{.IP}}_, _{{.Port}}_, _{{.Target}}_ (user@host), and _{{.Address}}_ (ip:port).

*-exec-command* _command_
	Start this shell command when a touch is required and terminate it once the touch is registered, e.g. a dialog window that stays visible until the YubiKey is touched. The command is run with *sh -c*; _{{.Reasons}}_ expands to the active event types and _{{.Details}}_ to the request details, e.g. the SSH host.

The notification title and body use Go template syntax. _{{.Reasons}}_ expands to a sorted, comma-separated list of active event types: _gpg_, _hmac_, and _u2f_. _{{.Details}}_ describes the request, such as the SSH host (with IP and port) that is waiting for the touch; it is empty when unknown. Its format is set with *-details-template*.

*-no-socket*
	Disable unix socket notifier.

*-stdout*
	Print notifications to stdout.

*-dbus*
	Support notifications via dbus SessionBus.

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

_YUBIKEY_TOUCH_DETECTOR_NOTIFY_
	Equivalent to specifying *-notify*.

_YUBIKEY_TOUCH_DETECTOR_NOTIFY_TITLE_
	Equivalent to specifying *-notify-title*.

_YUBIKEY_TOUCH_DETECTOR_NOTIFY_BODY_
	Equivalent to specifying *-notify-body*.

_YUBIKEY_TOUCH_DETECTOR_NOTIFY_URGENCY_
	Equivalent to specifying *-notify-urgency*.

_YUBIKEY_TOUCH_DETECTOR_EXEC_COMMAND_
	Equivalent to specifying *-exec-command*.

_YUBIKEY_TOUCH_DETECTOR_DETAILS_TEMPLATE_
	Equivalent to specifying *-details-template*.

_YUBIKEY_TOUCH_DETECTOR_STDOUT_
	Equivalent to specifying *-stdout*.

_YUBIKEY_TOUCH_DETECTOR_NOSOCKET_
	Equivalent to specifying *-no-socket*.

_YUBIKEY_TOUCH_DETECTOR_DBUS_
	Equivalent to specifying *-dbus*.

# FILES

_$XDG_RUNTIME_DIR/yubikey-touch-detector.socket_
	The socket exposing events on Linux.

_$TMPDIR/yubikey-touch-detector.socket_
	The socket exposing events on macOS.

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
