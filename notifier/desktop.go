package notifier

import (
	"bytes"
	"fmt"
	"text/template"
)

const DefaultNotificationTitle = "YubiKey is waiting for a touch"
const DefaultNotificationBody = "Touch your YubiKey to continue ({{.Reasons}})."

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
