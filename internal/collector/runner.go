package collector

import (
	"context"
	"encoding/json"
	"fmt"
	stdlog "log"
	"net/http"

	"github.com/asadQ-dev/threat-shield/internal/db"
	"github.com/asadQ-dev/threat-shield/internal/model"
	"github.com/asadQ-dev/threat-shield/internal/scoring"
	"github.com/jackc/pgx/v5/pgxpool"
)

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

func CollectData(ctx context.Context, conn *pgxpool.Pool, scorer *scoring.ThreatScorer, feedUrl string) error {
	stdlog.Printf("Starting data collection from CISA KEV feed")
	vulnerabilitiesProcessed := 0
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedUrl, nil)
	if err != nil {
		stdlog.Printf("Failed to create request: %v", err)
		return err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		stdlog.Printf("Failed to perform request: %v", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		err := fmt.Errorf("unexpected HTTP status: %s", resp.Status)
		stdlog.Printf("Request failed: %v", err)
		return err
	}
	var kevFeed model.CISAFeed
	err = json.NewDecoder(resp.Body).Decode(&kevFeed)
	if err != nil {
		stdlog.Printf("Failed to decode response: %v", err)
		return err
	}
	stdlog.Printf("Successfully fetched %d vulnerabilities", len(kevFeed.Vulnerabilities))
	for _, item := range kevFeed.Vulnerabilities {
		v := model.Vulnerability{
			ID:            item.CVEID,
			Title:         item.VulnerabilityName,
			Description:   item.ShortDescription,
			Source:        "CISA KEV",
			Date:          item.DateAdded,
			RansomwareUse: item.KnownRansomwareUse,
			DueDate:       item.DueDate,
			ThreatIndex:   0,
		}
		v.ThreatIndex = scorer.EvaluateVulnerability(v)
		if err := db.UpsertVulnerability(ctx, conn, v); err != nil {
			stdlog.Printf("Failed to persist vulnerability: %v (processed=%d)", err, vulnerabilitiesProcessed)
			return err
		}
		if err := db.RecordHistory(ctx, conn, v); err != nil {
			stdlog.Printf("Failed to record history: %v (processed=%d)", err, vulnerabilitiesProcessed)
			return err
		}
		vulnerabilitiesProcessed++
	}
	stdlog.Printf("Collection completed: fetched=%d processed=%d", len(kevFeed.Vulnerabilities), vulnerabilitiesProcessed)
	return nil
}
