package notifier

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"text/template"
)

// DefaultDetailsTemplate describes the request that is waiting for a touch
const DefaultDetailsTemplate = "SSH to {{.Target}} ({{.Address}})"

// TouchContext describes the request that is waiting for a touch, e.g. the
// SSH session that asked for a signature. The zero value means unknown.
type TouchContext struct {
	User string
	Host string
	IP   string
	Port string
}

// DetailsData is the data available to the details template
type DetailsData struct {
	// User is the login name, e.g. "alice"
	User string
	// Host is the host as typed, e.g. "prod-db" or "10.0.0.5"
	Host string
	// IP is the address the connection goes to
	IP string
	// Port is the remote port, e.g. "22"
	Port string
	// Target is "user@host", or just the host when no user is known
	Target string
	// Address is "ip:port", or just the IP when no port is known
	Address string
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

// unsafeDetailChars removes anything that could break out of a shell argument
// when a detected value is substituted into --exec-command.
var unsafeDetailChars = regexp.MustCompile(`[^A-Za-z0-9 .,_@:\[\]()/-]`)

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
	ctx = TouchContext{
		User: unsafeDetailChars.ReplaceAllString(ctx.User, ""),
		Host: unsafeDetailChars.ReplaceAllString(ctx.Host, ""),
		IP:   unsafeDetailChars.ReplaceAllString(ctx.IP, ""),
		Port: unsafeDetailChars.ReplaceAllString(ctx.Port, ""),
	}
	if ctx == (TouchContext{}) {
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
	if ctx.User != "" {
		target = ctx.User + "@" + host
	}
	address := ctx.IP
	if ctx.Port != "" {
		address = net.JoinHostPort(ctx.IP, ctx.Port)
	}
	return DetailsData{
		User:    ctx.User,
		Host:    ctx.Host,
		IP:      ctx.IP,
		Port:    ctx.Port,
		Target:  target,
		Address: address,
	}
}
