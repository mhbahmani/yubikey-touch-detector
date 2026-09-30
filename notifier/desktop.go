package notifier

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/esiqveland/notify"
)

const DefaultNotificationTitle = "YubiKey is waiting for a touch"
const DefaultNotificationBody = "Touch your YubiKey to continue ({{.Reasons}})."
const DefaultNotificationUrgency = "normal"

type notificationTemplateData struct {
	Reasons string
}

type notificationTemplates struct {
	title *template.Template
	body  *template.Template
}

func newNotificationTemplates(title, body string) (*notificationTemplates, error) {
	titleTemplate, err := template.New("notification title").Parse(title)
	if err != nil {
		return nil, fmt.Errorf("invalid notification title template: %w", err)
	}
	bodyTemplate, err := template.New("notification body").Parse(body)
	if err != nil {
		return nil, fmt.Errorf("invalid notification body template: %w", err)
	}
	return &notificationTemplates{title: titleTemplate, body: bodyTemplate}, nil
}

func (templates *notificationTemplates) render(reasons string) (string, string, error) {
	data := notificationTemplateData{Reasons: reasons}
	var title bytes.Buffer
	if err := templates.title.Execute(&title, data); err != nil {
		return "", "", fmt.Errorf("rendering notification title: %w", err)
	}
	var body bytes.Buffer
	if err := templates.body.Execute(&body, data); err != nil {
		return "", "", fmt.Errorf("rendering notification body: %w", err)
	}
	return title.String(), body.String(), nil
}

// newNotificationUrgency parses a desktop notification urgency level.
// Notification daemons typically keep "critical" notifications on screen
// until they are explicitly closed, which suits touch prompts well.
func newNotificationUrgency(urgency string) (notify.Urgency, error) {
	switch strings.ToLower(strings.TrimSpace(urgency)) {
	case "low":
		return notify.UrgencyLow, nil
	case "normal":
		return notify.UrgencyNormal, nil
	case "critical":
		return notify.UrgencyCritical, nil
	default:
		return notify.UrgencyNormal, fmt.Errorf("invalid notification urgency %q, expected one of: low, normal, critical", urgency)
	}
}
