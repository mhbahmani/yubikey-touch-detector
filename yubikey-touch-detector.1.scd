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

*-ssh-details* _template_
	Go template describing a request from an ssh client. Defaults to "SSH to {{.Target}} ({{.Address}}) {{.FromApp}}". Fields: _{{.Target}}_ (user@host, or "one of" and the possible addresses for concurrent requests), _{{.Address}}_ (ip:port), _{{.App}}_ (the application that started ssh, e.g. "Cursor" when an IDE runs git; empty for commands typed in a terminal), _{{.FromApp}}_ ("from" and the application, or empty), _{{.User}}_, _{{.Host}}_ (as typed), _{{.IP}}_, and _{{.Port}}_. Applications are named after their desktop entry.

*-ansible-details* _template_
	Go template describing ssh requests started by ansible. Defaults to "Ansible to:" followed by _{{.Hosts}}_ on a new line. _{{.Hosts}}_ lists the server IPs, one "- ip" per line.

*-app-details* _template_
	Go template describing a request from any other program. Defaults to "requested by {{.Requester}}". _{{.Requester}}_ names the program after its desktop entry, e.g. "Brave Web Browser", "Cursor via gpg" when an application has git run a signing tool (gpg, gpg2, gpgsm, or ssh-keygen), "git via gpg" for the same command typed in a terminal, or "PID 12345" when the name cannot be read. _{{.Process}}_, _{{.PID}}_, and _{{.Via}}_ hold the parts separately.

*-details-template* _template_
	Advanced: describe every kind of request with this one Go template instead of the three above. Accepts all of their fields, plus _{{.Ansible}}_, which is true for ansible requests.

	In all details templates, brackets left empty by a missing value are dropped and extra spaces collapsed, e.g. "SSH to host () from Cursor" becomes "SSH to host from Cursor". Requesting programs and SSH details are detected on Linux only.

*-popup*
	Show the built-in touch dialog (Linux only) while a touch is required. Press Escape or click the dialog to dismiss it early.

*-popup-position* _position_
	Where to show the touch dialog on the monitor under the pointer: center, top, bottom, left, right, top-left, top-right, bottom-left, or bottom-right. Defaults to "center". The dialog stays above other windows. Use "auto" to let the window manager place it. Wayland does not let windows choose their position, so in a Wayland session a positioned dialog runs through XWayland when it is available.

The notification title and body use Go template syntax. _{{.Reasons}}_ expands to a sorted, comma-separated list of active event types: _gpg_, _hmac_, and _u2f_. _{{.Details}}_ describes the request, such as the SSH host (with IP and port) that is waiting for the touch; it is empty when unknown. Its format is set with *-ssh-details*, *-ansible-details*, and *-app-details*.

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

# POPUP

*popup* [_reason_] [_details_]
	Show the built-in touch dialog (Linux only) until the process is terminated. Started by the app itself when *-popup* is given; not normally called by hand.

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

_YUBIKEY_TOUCH_DETECTOR_POPUP_
	Equivalent to specifying *-popup*.

_YUBIKEY_TOUCH_DETECTOR_POPUP_POSITION_
	Equivalent to specifying *-popup-position*.

_YUBIKEY_TOUCH_DETECTOR_SSH_DETAILS_
	Equivalent to specifying *-ssh-details*.

_YUBIKEY_TOUCH_DETECTOR_ANSIBLE_DETAILS_
	Equivalent to specifying *-ansible-details*.

_YUBIKEY_TOUCH_DETECTOR_APP_DETAILS_
	Equivalent to specifying *-app-details*.

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
