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
	defer SetDetailsTemplates(DetailsTemplates{})

	if err := SetDetailsTemplates(DetailsTemplates{SSH: "{{.User}} at {{.Host}} [{{.IP}}]"}); err != nil {
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
	for _, templates := range []DetailsTemplates{
		{SSH: "{{.User"},
		{Ansible: "{{.Hosts"},
		{App: "{{.Requester"},
		{Override: "{{.User"},
	} {
		if err := SetDetailsTemplates(templates); err == nil {
			t.Fatalf("SetDetailsTemplates(%+v) accepted an invalid template", templates)
		}
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
	defer SetDetailsTemplates(DetailsTemplates{})

	if err := SetDetailsTemplates(DetailsTemplates{App: "{{.Process}} [{{.PID}}]"}); err != nil {
		t.Fatal(err)
	}
	remove := AddTouchContext(TouchContext{Process: "git", PID: 4242})
	defer remove()

	if got := touchDetails(); got != "git [4242]" {
		t.Fatalf("touchDetails() = %q", got)
	}
}

func TestConcurrentSSHDetails(t *testing.T) {
	defer SetDetailsTemplates(DetailsTemplates{})
	remove := AddTouchContext(TouchContext{SSHCandidates: "10.60.12.129:22, 10.60.12.130:22, 10.60.12.132:22"})
	defer remove()
	want := "SSH to one of 10.60.12.129:22, 10.60.12.130:22, 10.60.12.132:22"
	for _, templates := range []DetailsTemplates{
		{},
		{SSH: "SSH to {{.Target}} [{{.Address}}]"},
		{Override: "{{if .Process}}requested by {{.Process}}{{else}}SSH to {{.Target}}{{with .Address}} [{{.}}]{{end}}{{end}}"},
	} {
		if err := SetDetailsTemplates(templates); err != nil {
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

func TestEachKindUsesItsOwnTemplate(t *testing.T) {
	defer SetDetailsTemplates(DetailsTemplates{})
	if err := SetDetailsTemplates(DetailsTemplates{
		SSH:     "ssh {{.Target}} [{{.Address}}]",
		Ansible: "ansible {{.Hosts}}",
		App:     "app {{.Requester}}",
	}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		ctx  TouchContext
		want string
	}{
		{"ssh", TouchContext{User: "alice", Host: "db", IP: "10.0.0.5", Port: "22"}, "ssh alice@db [10.0.0.5:22]"},
		{"ssh without address", TouchContext{User: "alice", Host: "db"}, "ssh alice@db"},
		{"ansible", TouchContext{IP: "10.0.0.5", Port: "22", Ansible: true}, "ansible - 10.0.0.5"},
		{"app via tool", TouchContext{Process: "git", PID: 4242, Via: "gpg"}, "app git via gpg"},
		{"app", TouchContext{Process: "firefox", PID: 4242}, "app firefox"},
		{"app without name", TouchContext{PID: 4242}, "app PID 4242"},
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

func TestEmptyKindTemplateKeepsDefault(t *testing.T) {
	defer SetDetailsTemplates(DetailsTemplates{})
	if err := SetDetailsTemplates(DetailsTemplates{SSH: "custom {{.Target}}"}); err != nil {
		t.Fatal(err)
	}
	remove := AddTouchContext(TouchContext{Process: "git", Via: "gpg"})
	defer remove()
	if got := touchDetails(); got != "requested by git via gpg" {
		t.Fatalf("touchDetails() = %q, want the default app details", got)
	}
}

func TestOverrideDescribesEveryKind(t *testing.T) {
	defer SetDetailsTemplates(DetailsTemplates{})
	if err := SetDetailsTemplates(DetailsTemplates{
		App:      "ignored",
		Override: "{{if .Process}}app {{.Process}}{{else}}ssh {{.Target}}{{end}}",
	}); err != nil {
		t.Fatal(err)
	}
	removeApp := AddTouchContext(TouchContext{Process: "git"})
	defer removeApp()
	removeSSH := AddTouchContext(TouchContext{Host: "db"})
	defer removeSSH()
	if got := touchDetails(); got != "app git, ssh db" {
		t.Fatalf("touchDetails() = %q", got)
	}
}
