package notifier

import (
	"fmt"
	"strings"
)

// DefaultPopupPosition places the touch dialog in the middle of the screen
const DefaultPopupPosition = "center"

// PopupPositions lists where the touch dialog can be placed. "auto" leaves
// the choice to the window manager.
var PopupPositions = []string{
	"center",
	"top", "bottom", "left", "right",
	"top-left", "top-right", "bottom-left", "bottom-right",
	"auto",
}

// The detector hands the dialog its content through these variables rather
// than its command line, which every local user can read through ps
const (
	PopupReasonsEnv  = "YUBIKEY_TOUCH_DETECTOR_POPUP_REASONS"
	PopupDetailsEnv  = "YUBIKEY_TOUCH_DETECTOR_POPUP_DETAILS"
	PopupPositionEnv = "YUBIKEY_TOUCH_DETECTOR_POPUP_POSITION"
)

// ValidatePopupPosition reports whether position is one of PopupPositions
func ValidatePopupPosition(position string) error {
	for _, valid := range PopupPositions {
		if position == valid {
			return nil
		}
	}
	return fmt.Errorf("invalid popup position %q, expected one of: %s", position, strings.Join(PopupPositions, ", "))
}
