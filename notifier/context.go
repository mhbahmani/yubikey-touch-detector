package notifier

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// touchContexts describes what the active YubiKey operations are for, e.g. the
// SSH host that requested a signature. Detectors add an entry when a request
// starts and call the returned function when it ends.
var touchContexts = struct {
	sync.Mutex
	nextID  uint64
	entries map[uint64]string
}{entries: make(map[uint64]string)}

// unsafeDetailChars removes anything that could break out of a shell argument
// when the details are substituted into --exec-command.
var unsafeDetailChars = regexp.MustCompile(`[^A-Za-z0-9 .,_@:\[\]()/-]`)

// AddTouchContext records a human-readable description of a YubiKey operation
// and returns a function that removes it again.
func AddTouchContext(detail string) (remove func()) {
	detail = unsafeDetailChars.ReplaceAllString(detail, "")

	touchContexts.Lock()
	touchContexts.nextID++
	id := touchContexts.nextID
	touchContexts.entries[id] = detail
	touchContexts.Unlock()

	return func() {
		touchContexts.Lock()
		delete(touchContexts.entries, id)
		touchContexts.Unlock()
	}
}

// touchDetails returns the distinct descriptions currently recorded, sorted and
// joined on one line.
func touchDetails() string {
	touchContexts.Lock()
	defer touchContexts.Unlock()

	seen := make(map[string]bool, len(touchContexts.entries))
	details := make([]string, 0, len(touchContexts.entries))
	for _, detail := range touchContexts.entries {
		if detail != "" && !seen[detail] {
			seen[detail] = true
			details = append(details, detail)
		}
	}
	sort.Strings(details)
	return strings.Join(details, ", ")
}
