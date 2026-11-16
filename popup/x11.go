//go:build linux

package popup

/*
#cgo pkg-config: x11
#cgo LDFLAGS: -ldl

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <dlfcn.h>
#include <string.h>

// Mirrors XineramaScreenInfo; libXinerama is loaded at runtime, so building
// needs no Xinerama headers and the dialog still works without the library
typedef struct {
	int screen_number;
	short x_org, y_org, width, height;
} ytd_screen_info;

// ytd_monitor finds the monitor under the pointer, falling back to the first
// monitor and then to the whole screen
static void ytd_monitor(Display *d, int *x, int *y, int *w, int *h) {
	int screen = DefaultScreen(d);
	*x = 0;
	*y = 0;
	*w = DisplayWidth(d, screen);
	*h = DisplayHeight(d, screen);

	Window root, child;
	int px = 0, py = 0, wx, wy;
	unsigned int mask;
	Bool pointer = XQueryPointer(d, DefaultRootWindow(d), &root, &child, &px, &py, &wx, &wy, &mask);

	void *lib = dlopen("libXinerama.so.1", RTLD_LAZY);
	if (!lib) {
		return;
	}
	Bool (*active)(Display *) = (Bool (*)(Display *))dlsym(lib, "XineramaIsActive");
	ytd_screen_info *(*query)(Display *, int *) = (ytd_screen_info *(*)(Display *, int *))dlsym(lib, "XineramaQueryScreens");
	if (active && query && active(d)) {
		int count = 0;
		ytd_screen_info *screens = query(d, &count);
		if (screens && count > 0) {
			int pick = 0;
			for (int i = 0; pointer && i < count; i++) {
				if (px >= screens[i].x_org && px < screens[i].x_org + screens[i].width &&
				    py >= screens[i].y_org && py < screens[i].y_org + screens[i].height) {
					pick = i;
					break;
				}
			}
			*x = screens[pick].x_org;
			*y = screens[pick].y_org;
			*w = screens[pick].width;
			*h = screens[pick].height;
		}
		if (screens) {
			XFree(screens);
		}
	}
	dlclose(lib);
}

// ytd_undecorate asks the window manager not to frame the window. Gio's X11
// backend always leaves decorations on, so GNOME would add a title bar.
static void ytd_undecorate(Display *d, Window w) {
	// MWM_HINTS_DECORATIONS with no decorations
	unsigned long hints[5] = {2, 0, 0, 0, 0};
	Atom motif = XInternAtom(d, "_MOTIF_WM_HINTS", False);
	XChangeProperty(d, w, motif, motif, 32, PropModeReplace, (unsigned char *)hints, 5);
	XFlush(d);
}

// ytd_place moves the window and asks the window manager to keep it there
// and above other windows
static void ytd_place(Display *d, Window w, int x, int y) {
	XSizeHints *hints = XAllocSizeHints();
	if (hints) {
		long supplied;
		XGetWMNormalHints(d, w, hints, &supplied);
		hints->flags |= USPosition | PPosition;
		hints->x = x;
		hints->y = y;
		XSetWMNormalHints(d, w, hints);
		XFree(hints);
	}
	XMoveWindow(d, w, x, y);

	XEvent ev;
	memset(&ev, 0, sizeof(ev));
	ev.xclient.type = ClientMessage;
	ev.xclient.window = w;
	ev.xclient.message_type = XInternAtom(d, "_NET_WM_STATE", False);
	ev.xclient.format = 32;
	ev.xclient.data.l[0] = 1; // _NET_WM_STATE_ADD
	ev.xclient.data.l[1] = XInternAtom(d, "_NET_WM_STATE_ABOVE", False);
	ev.xclient.data.l[3] = 1; // sent by a normal application
	XSendEvent(d, DefaultRootWindow(d), False, SubstructureRedirectMask | SubstructureNotifyMask, &ev);
	XFlush(d);
}
*/
import "C"

import (
	"image"

	"gioui.org/app"
)

// undecorateX11 removes the window manager's frame, as the dialog draws its
// own card
func undecorateX11(view app.X11ViewEvent) {
	C.ytd_undecorate((*C.Display)(view.Display), C.Window(view.Window))
}

// placeX11 puts the window at position on the monitor under the pointer.
// Gio initializes Xlib for use from several threads, so calling it from the
// event loop is safe.
func placeX11(view app.X11ViewEvent, position string, size image.Point, margin int) {
	display := (*C.Display)(view.Display)
	var x, y, w, h C.int
	C.ytd_monitor(display, &x, &y, &w, &h)
	monitor := image.Rect(int(x), int(y), int(x+w), int(y+h))
	at := origin(position, monitor, size, margin)
	C.ytd_place(display, C.Window(view.Window), C.int(at.X), C.int(at.Y))
}
