package notifier

import "testing"

func TestTouchContextsAreAddedAndRemoved(t *testing.T) {
	removeFirst := AddTouchContext(TouchContext{User: "alice", Host: "example.com", IP: "10.0.0.5", Port: "22"})
	removeSecond := AddTouchContext(TouchContext{User: "bob", Host: "example.org", IP: "10.0.0.6", Port: "22"})
	removeDuplicate := AddTouchContext(TouchContext{User: "alice", Host: "example.com", IP: "10.0.0.5", Port: "22"})

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

func TestEmptyTouchContextIsIgnored(t *testing.T) {
	remove := AddTouchContext(TouchContext{})
	defer remove()
	if got := touchDetails(); got != "" {
		t.Fatalf("touchDetails() = %q, want empty", got)
	}
}

func TestTouchContextValuesAreSanitized(t *testing.T) {
	remove := AddTouchContext(TouchContext{User: "a;b", Host: "x$(rm -rf ~)'`id`", IP: "10.0.0.5", Port: "22"})
	defer remove()

	if got := touchDetails(); got != "SSH to ab@x(rm -rf )id (10.0.0.5:22)" {
		t.Fatalf("touchDetails() = %q, unsafe characters were not removed", got)
	}
}

func TestDefaultNotificationBodyIncludesDetails(t *testing.T) {
	remove := AddTouchContext(TouchContext{User: "alice", Host: "example.com", IP: "10.0.0.5", Port: "22"})
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

func TestCustomDetailsTemplate(t *testing.T) {
	defer SetDetailsTemplate(DefaultDetailsTemplate)

	if err := SetDetailsTemplate("{{.User}} at {{.Host}} [{{.IP}}]"); err != nil {
		t.Fatal(err)
	}
	remove := AddTouchContext(TouchContext{User: "alice", Host: "prod-db", IP: "10.0.0.5", Port: "22"})
	defer remove()

	if got := touchDetails(); got != "alice at prod-db [10.0.0.5]" {
		t.Fatalf("touchDetails() = %q", got)
	}
}

func TestHostFallsBackToIPInTarget(t *testing.T) {
	remove := AddTouchContext(TouchContext{IP: "10.0.0.5"})
	defer remove()

	if got := touchDetails(); got != "SSH to 10.0.0.5 (10.0.0.5)" {
		t.Fatalf("touchDetails() = %q", got)
	}
}

func TestInvalidDetailsTemplateIsRejected(t *testing.T) {
	if err := SetDetailsTemplate("{{.User"); err == nil {
		t.Fatal("SetDetailsTemplate accepted an invalid template")
	}
}
