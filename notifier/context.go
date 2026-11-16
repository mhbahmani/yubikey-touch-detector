package notifier

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"text/template"
)

// DefaultDetailsTemplate describes the request that is waiting for a touch
const DefaultDetailsTemplate = "{{if .Ansible}}Ansible to:\n{{.Target}}{{else if .Process}}requested by {{.Process}}{{with .Via}} via {{.}}{{end}}{{else if .PID}}requested by PID {{.PID}}{{else}}SSH to {{.Target}}{{with .Address}} ({{.}}){{end}}{{end}}"

// TouchContext describes the request that is waiting for a touch, e.g. the
// SSH session that asked for a signature. The zero value means unknown.
type TouchContext struct {
	User string
	Host string
	IP   string
	Port string
	// Process names the application making the request when it is not ssh,
	// e.g. a browser doing a WebAuthn operation
	Process string
	// PID identifies that application; it is set even when the name cannot
	// be read, e.g. because the process already exited
	PID int
	// Via names the tool that talks to the key on behalf of Process, e.g. gpg
	// when git signs a commit
	Via string
	// SSHCandidates lists possible destinations when a shared agent has concurrent requests.
	SSHCandidates string
	Ansible       bool
}

// DetailsData is the data available to the details template
type DetailsData struct {
	User    string
	Host    string
	IP      string
	Port    string
	Process string
	PID     int
	Via     string
	Target  string
	Address string
	Ansible bool
}

// touchContexts tracks the requests that are waiting for a touch. Detectors
// add an entry when a request starts and call the returned function when it
// ends.
var touchContexts = struct {
	sync.Mutex
	nextID   uint64
	entries  map[uint64]TouchContext
	template *template.Template
}{
	entries:  make(map[uint64]TouchContext),
	template: template.Must(template.New("details").Parse(DefaultDetailsTemplate)),
}

// SetDetailsTemplate sets the template that describes each request, e.g.
// "SSH to {{.Target}} ({{.Address}})"
func SetDetailsTemplate(text string) error {
	parsed, err := template.New("details").Parse(text)
	if err != nil {
		return fmt.Errorf("invalid details template: %w", err)
	}
	touchContexts.Lock()
	touchContexts.template = parsed
	touchContexts.Unlock()
	return nil
}

// AddTouchContext records the request that is waiting for a touch and returns
// a function that removes it again. Empty contexts are ignored.
func AddTouchContext(ctx TouchContext) (remove func()) {
	if ctx.Process == "" && ctx.PID == 0 && ctx.Host == "" && ctx.IP == "" && ctx.SSHCandidates == "" {
		return func() {}
	}

	touchContexts.Lock()
	touchContexts.nextID++
	id := touchContexts.nextID
	touchContexts.entries[id] = ctx
	touchContexts.Unlock()

	return func() {
		touchContexts.Lock()
		delete(touchContexts.entries, id)
		touchContexts.Unlock()
	}
}

// touchDetails renders every recorded request with the details template,
// returning the distinct results sorted and joined on one line.
func touchDetails() string {
	touchContexts.Lock()
	defer touchContexts.Unlock()

	seen := make(map[string]bool, len(touchContexts.entries))
	details := make([]string, 0, len(touchContexts.entries))
	for _, ctx := range touchContexts.entries {
		var rendered bytes.Buffer
		if err := touchContexts.template.Execute(&rendered, newDetailsData(ctx)); err != nil {
			continue
		}
		detail := strings.TrimSpace(rendered.String())
		if detail != "" && !seen[detail] {
			seen[detail] = true
			details = append(details, detail)
		}
	}
	sort.Strings(details)
	return strings.Join(details, ", ")
}

func newDetailsData(ctx TouchContext) DetailsData {
	host := ctx.Host
	if host == "" {
		host = ctx.IP
	}
	target := host
	if ctx.User != "" && host != "" {
		target = ctx.User + "@" + host
	}
	if target == "" && ctx.SSHCandidates != "" {
		target = "one of " + ctx.SSHCandidates
	}
	if ctx.Ansible {
		if ctx.SSHCandidates != "" {
			target = "- " + strings.ReplaceAll(ctx.SSHCandidates, "\n", "\n- ")
		} else {
			target = "- " + host
			if ctx.IP != "" {
				target = "- " + ctx.IP
			}
		}
	}
	address := ctx.IP
	if ctx.IP != "" && ctx.Port != "" {
		address = net.JoinHostPort(ctx.IP, ctx.Port)
	}
	return DetailsData{
		User:    ctx.User,
		Host:    ctx.Host,
		IP:      ctx.IP,
		Port:    ctx.Port,
		Process: ctx.Process,
		PID:     ctx.PID,
		Via:     ctx.Via,
		Target:  target,
		Address: address,
		Ansible: ctx.Ansible,
	}
}
