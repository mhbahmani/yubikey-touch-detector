package notifier

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

// Default templates for each kind of request that waits for a touch
const (
	DefaultSSHDetails     = "SSH to {{.Target}} ({{.Address}})"
	DefaultAnsibleDetails = "Ansible to:\n{{.Hosts}}"
	DefaultAppDetails     = "requested by {{.Requester}}"
)

// DetailsTemplates describes requests with one template per kind, so no
// template needs conditionals. Empty fields keep the default.
type DetailsTemplates struct {
	// SSH describes an ssh client, or several possible ones
	SSH string
	// Ansible describes ssh clients started by ansible
	Ansible string
	// App describes any other program, e.g. a browser or git running gpg
	App string
	// Override, when set, describes every request with this one template
	// instead, for full control
	Override string
}

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

// DetailsData is the data available to the details templates
type DetailsData struct {
	User    string
	Host    string
	IP      string
	Port    string
	Process string
	PID     int
	Via     string
	// Requester names the program, e.g. "git via gpg", "firefox", or
	// "PID 1234" when the name is unknown
	Requester string
	Target    string
	Address   string
	// Hosts lists Ansible destinations, one "- ip" per line
	Hosts   string
	Ansible bool
}

type detailsKind int

const (
	sshDetails detailsKind = iota
	ansibleDetails
	appDetails
)

func (ctx TouchContext) kind() detailsKind {
	switch {
	case ctx.Ansible:
		return ansibleDetails
	case ctx.Process != "" || ctx.PID != 0:
		return appDetails
	default:
		return sshDetails
	}
}

// touchContexts tracks the requests that are waiting for a touch. Detectors
// add an entry when a request starts and call the returned function when it
// ends.
var touchContexts = struct {
	sync.Mutex
	nextID    uint64
	entries   map[uint64]TouchContext
	templates map[detailsKind]*template.Template
}{
	entries:   make(map[uint64]TouchContext),
	templates: mustParseDetails(DetailsTemplates{}),
}

func mustParseDetails(templates DetailsTemplates) map[detailsKind]*template.Template {
	parsed, err := parseDetails(templates)
	if err != nil {
		panic(err)
	}
	return parsed
}

func parseDetails(templates DetailsTemplates) (map[detailsKind]*template.Template, error) {
	texts := map[detailsKind]struct{ name, text, fallback string }{
		sshDetails:     {"ssh", templates.SSH, DefaultSSHDetails},
		ansibleDetails: {"ansible", templates.Ansible, DefaultAnsibleDetails},
		appDetails:     {"app", templates.App, DefaultAppDetails},
	}
	parsed := make(map[detailsKind]*template.Template, len(texts))
	for kind, entry := range texts {
		text := entry.text
		if templates.Override != "" {
			text, entry.name = templates.Override, "override"
		} else if text == "" {
			text = entry.fallback
		}
		tmpl, err := template.New(entry.name).Parse(text)
		if err != nil {
			return nil, fmt.Errorf("invalid %s details template: %w", entry.name, err)
		}
		parsed[kind] = tmpl
	}
	return parsed, nil
}

// SetDetailsTemplates sets the templates that describe each kind of request
func SetDetailsTemplates(templates DetailsTemplates) error {
	parsed, err := parseDetails(templates)
	if err != nil {
		return err
	}
	touchContexts.Lock()
	touchContexts.templates = parsed
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

// emptyBrackets matches brackets left empty by a missing value, e.g. the
// address in "SSH to host ()"
var emptyBrackets = regexp.MustCompile(`[ \t]*(\(\s*\)|\[\s*\])`)

// touchDetails renders every recorded request with the template for its
// kind, returning the distinct results sorted and joined on one line.
func touchDetails() string {
	touchContexts.Lock()
	defer touchContexts.Unlock()

	seen := make(map[string]bool, len(touchContexts.entries))
	details := make([]string, 0, len(touchContexts.entries))
	for _, ctx := range touchContexts.entries {
		var rendered bytes.Buffer
		if err := touchContexts.templates[ctx.kind()].Execute(&rendered, newDetailsData(ctx)); err != nil {
			continue
		}
		detail := strings.TrimSpace(emptyBrackets.ReplaceAllString(rendered.String(), ""))
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
	var hosts string
	if ctx.Ansible {
		switch {
		case ctx.SSHCandidates != "":
			hosts = "- " + strings.ReplaceAll(ctx.SSHCandidates, "\n", "\n- ")
		case ctx.IP != "":
			hosts = "- " + ctx.IP
		case host != "":
			hosts = "- " + host
		}
		target = hosts
	}
	address := ctx.IP
	if ctx.IP != "" && ctx.Port != "" {
		address = net.JoinHostPort(ctx.IP, ctx.Port)
	}
	return DetailsData{
		User:      ctx.User,
		Host:      ctx.Host,
		IP:        ctx.IP,
		Port:      ctx.Port,
		Process:   ctx.Process,
		PID:       ctx.PID,
		Via:       ctx.Via,
		Requester: requester(ctx),
		Target:    target,
		Address:   address,
		Hosts:     hosts,
		Ansible:   ctx.Ansible,
	}
}

// requester names the program behind a request, e.g. "git via gpg"
func requester(ctx TouchContext) string {
	switch {
	case ctx.Process != "" && ctx.Via != "":
		return ctx.Process + " via " + ctx.Via
	case ctx.Process != "":
		return ctx.Process
	case ctx.PID != 0:
		return "PID " + strconv.Itoa(ctx.PID)
	}
	return ""
}
