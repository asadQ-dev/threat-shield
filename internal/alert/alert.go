package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/asadQ-dev/threat-shield/internal/model"
)

func SendNewVulnerabilityAlert(vuln model.Vulnerability) error {
	webhookURL := os.Getenv("ALERT_WEBHOOK_URL")
	if webhookURL == "" {
		return fmt.Errorf("ALERT_WEBHOOK_URL is not configured")
	}
	message := fmt.Sprintf(
		"**New vulnerability added: %s**\n%s\nThreat index: %.2f\nDue date: %s",
		vuln.ID, vuln.Title, vuln.ThreatIndex, vuln.DueDate,
	)
	payload, err := json.Marshal(map[string]string{"content": message})
	if err != nil {
		return fmt.Errorf("failed to encode alert payload: %w", err)
	}
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to send alert: %w", err)
	}
	defer resp.Body.Close()
	fmt.Printf("New Vulnerability Alert sent for %s\n", vuln.ID)
	return nil
}
