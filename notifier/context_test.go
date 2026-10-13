package notifier

import "testing"

func TestTouchContextsAreAddedAndRemoved(t *testing.T) {
	removeFirst := AddTouchContext("SSH to alice@example.com (10.0.0.5:22)")
	removeSecond := AddTouchContext("SSH to bob@example.org (10.0.0.6:22)")
	removeDuplicate := AddTouchContext("SSH to alice@example.com (10.0.0.5:22)")

	want := "SSH to alice@example.com (10.0.0.5:22), SSH to bob@example.org (10.0.0.6:22)"
	if got := touchDetails(); got != want {
		t.Fatalf("touchDetails() = %q, want %q", got, want)
	}

	removeDuplicate()
	removeFirst()
	if got := touchDetails(); got != "SSH to bob@example.org (10.0.0.6:22)" {
		t.Fatalf("after removal touchDetails() = %q", got)
	}

	removeSecond()
	if got := touchDetails(); got != "" {
		t.Fatalf("after all removed touchDetails() = %q, want empty", got)
	}
}

func TestTouchContextIsSanitized(t *testing.T) {
	remove := AddTouchContext("SSH to x$(rm -rf ~)'; echo `id`")
	defer remove()

	// Parentheses are kept for the "(ip:port)" format, so templates should quote {{.Details}}
	if got := touchDetails(); got != "SSH to x(rm -rf ) echo id" {
		t.Fatalf("touchDetails() = %q, shell metacharacters were not removed", got)
	}
}

func TestDefaultNotificationBodyIncludesDetails(t *testing.T) {
	remove := AddTouchContext("SSH to alice@example.com (10.0.0.5:22)")
	defer remove()

	templates, err := newNotificationTemplates(DefaultNotificationTitle, DefaultNotificationBody)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := templates.render("gpg")
	if err != nil {
		t.Fatal(err)
	}
	want := "Touch your YubiKey to continue (gpg).\nSSH to alice@example.com (10.0.0.5:22)"
	if body != want {
		t.Fatalf("default body = %q, want %q", body, want)
	}
}
