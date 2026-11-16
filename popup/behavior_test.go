//go:build linux

package popup

import "testing"

func TestReasonText(t *testing.T) {
	for reasons, want := range map[string]string{
		"u2f":            "A security key is asking for a touch",
		"gpg":            "A GPG operation is waiting",
		"hmac":           "A challenge-response request is waiting",
		"gpg, u2f":       "Several requests are waiting",
		"gpg, hmac, u2f": "Several requests are waiting",
		"":               "A request is waiting",
		"other":          "A request is waiting",
	} {
		if got := reasonText(reasons); got != want {
			t.Errorf("reasonText(%q) = %q, want %q", reasons, got, want)
		}
	}
}
