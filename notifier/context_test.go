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

func TestTouchContextValuesArePreserved(t *testing.T) {
	remove := AddTouchContext(TouchContext{Process: "Firefox β"})
	defer remove()

	if got := touchDetails(); got != "requested by Firefox β" {
		t.Fatalf("touchDetails() = %q, want process name unchanged", got)
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

func TestMissingAddressIsOmitted(t *testing.T) {
	remove := AddTouchContext(TouchContext{User: "alice", Host: "example.com"})
	defer remove()

	if got := touchDetails(); got != "SSH to alice@example.com" {
		t.Fatalf("touchDetails() = %q", got)
	}
}

func TestInvalidDetailsTemplateIsRejected(t *testing.T) {
	if err := SetDetailsTemplate("{{.User"); err == nil {
		t.Fatal("SetDetailsTemplate accepted an invalid template")
	}
}

func TestProcessOnlyContext(t *testing.T) {
	remove := AddTouchContext(TouchContext{Process: "firefox"})
	defer remove()

	if got := touchDetails(); got != "requested by firefox" {
		t.Fatalf("touchDetails() = %q, want %q", got, "requested by firefox")
	}
}

func TestProcessNameIsPreferredOverPID(t *testing.T) {
	remove := AddTouchContext(TouchContext{Process: "firefox", PID: 4242})
	defer remove()

	if got := touchDetails(); got != "requested by firefox" {
		t.Fatalf("touchDetails() = %q, want %q", got, "requested by firefox")
	}
}

func TestToolRunningOnBehalfOfAppIsNamed(t *testing.T) {
	remove := AddTouchContext(TouchContext{Process: "git", PID: 4242, Via: "gpg"})
	defer remove()

	if got := touchDetails(); got != "requested by git via gpg" {
		t.Fatalf("touchDetails() = %q, want %q", got, "requested by git via gpg")
	}
}

func TestPIDOnlyContext(t *testing.T) {
	remove := AddTouchContext(TouchContext{PID: 4242})
	defer remove()

	if got := touchDetails(); got != "requested by PID 4242" {
		t.Fatalf("touchDetails() = %q, want %q", got, "requested by PID 4242")
	}
}

func TestPIDInCustomDetailsTemplate(t *testing.T) {
	defer SetDetailsTemplate(DefaultDetailsTemplate)

	if err := SetDetailsTemplate("{{.Process}} [{{.PID}}]"); err != nil {
		t.Fatal(err)
	}
	remove := AddTouchContext(TouchContext{Process: "git", PID: 4242})
	defer remove()

	if got := touchDetails(); got != "git [4242]" {
		t.Fatalf("touchDetails() = %q", got)
	}
}

func TestConcurrentSSHDetails(t *testing.T) {
	defer SetDetailsTemplate(DefaultDetailsTemplate)
	remove := AddTouchContext(TouchContext{SSHCandidates: "10.60.12.129:22, 10.60.12.130:22, 10.60.12.132:22"})
	defer remove()
	want := "SSH to one of 10.60.12.129:22, 10.60.12.130:22, 10.60.12.132:22"
	for _, format := range []string{
		DefaultDetailsTemplate,
		"{{if .Process}}requested by {{.Process}}{{else}}SSH to {{.Target}}{{with .Address}} [{{.}}]{{end}}{{end}}",
	} {
		if err := SetDetailsTemplate(format); err != nil {
			t.Fatal(err)
		}
		if got := touchDetails(); got != want {
			t.Fatalf("touchDetails() = %q, want %q", got, want)
		}
	}
}

func TestAnsibleDetails(t *testing.T) {
	for _, test := range []struct {
		name string
		ctx  TouchContext
		want string
	}{
		{
			name: "parallel workers",
			ctx:  TouchContext{SSHCandidates: "10.60.12.129\n10.60.12.130", Ansible: true},
			want: "Ansible to:\n- 10.60.12.129\n- 10.60.12.130",
		},
		{
			name: "single worker",
			ctx:  TouchContext{Host: "worker-a", IP: "10.60.12.129", Port: "22", Ansible: true},
			want: "Ansible to:\n- 10.60.12.129",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			remove := AddTouchContext(test.ctx)
			defer remove()
			if got := touchDetails(); got != test.want {
				t.Fatalf("touchDetails() = %q, want %q", got, test.want)
			}
		})
	}
}
