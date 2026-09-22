package db

import (
	"context"
	"net/url"
	"testing"

	"github.com/asadQ-dev/threat-shield/internal/model"
)

func TestQueryExample(t *testing.T) {
	ctx := context.Background()
	conn, err := Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to the database: %v", err)
	}

	testVulnerability := model.Vulnerability{
		ID:            "CVE-TEST-1234",
		Title:         "Test Vulnerability",
		Description:   "This is a test vulnerability",
		Source:        "Testlevel",
		Date:          "2024-06-01",
		RansomwareUse: "Unknown",
		DueDate:       "2024-12-31",
		ThreatIndex:   75,
	}

	err = UpsertVulnerability(ctx, conn, testVulnerability)
	if err != nil {
		conn.Close()
		t.Fatalf("Failed to upsert test vulnerability: %v", err)
	}

	t.Cleanup(func() {
		cleanupConn, cleanErr := Connect(context.Background())
		if cleanErr == nil {
			_, _ = cleanupConn.Exec(context.Background(), "DELETE FROM vulnerabilities WHERE cve_id=$1", testVulnerability.ID)
			cleanupConn.Close()
		}
		conn.Close()
	})

	queryParams := url.Values{
		"search":    []string{"Test Vulnerability"},
		"min_score": []string{"50"},
		"sort":      []string{"threat_index"},
		"limit":     []string{"10"},
	}

	vulnerabilities, err := QueryVulnerabilities(ctx, conn, queryParams)
	if err != nil {
		t.Fatalf("Failed to query vulnerabilities: %v", err)
	}
	if len(vulnerabilities) == 0 {
		t.Fatalf("Expected to find at least one vulnerability")
	}
	result := vulnerabilities[0]
	if result.ID != testVulnerability.ID {
		t.Fatalf("Expected vulnerability ID %v, got %v", testVulnerability.ID, result.ID)
	}
	if result.Title != testVulnerability.Title {
		t.Fatalf("Expected vulnerability Title %v, got %v", testVulnerability.Title, result.Title)
	}
	if result.Description != testVulnerability.Description {
		t.Fatalf("Expected vulnerability Description %v, got %v", testVulnerability.Description, result.Description)
	}
	if result.Source != testVulnerability.Source {
		t.Fatalf("Expected vulnerability Source %v, got %v", testVulnerability.Source, result.Source)
	}
	if result.RansomwareUse != testVulnerability.RansomwareUse {
		t.Fatalf("Expected vulnerability RansomwareUse %v, got %v", testVulnerability.RansomwareUse, result.RansomwareUse)
	}
	if result.DueDate != testVulnerability.DueDate {
		t.Fatalf("Expected vulnerability DueDate %v, got %v", testVulnerability.DueDate, result.DueDate)
	}
	if result.ThreatIndex != testVulnerability.ThreatIndex {
		t.Fatalf("Expected vulnerability ThreatIndex %v, got %v", testVulnerability.ThreatIndex, result.ThreatIndex)
	}
}
func TestUpsertVulnerabilities(t *testing.T) {
	ctx := context.Background()
	conn, err := Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to the database: %v", err)
	}

	testID := "CVE-TEST-5678"
	t.Cleanup(func() {
		cleanupConn, cleanErr := Connect(context.Background())
		if cleanErr == nil {
			_, _ = cleanupConn.Exec(context.Background(), "DELETE FROM vulnerabilities WHERE cve_id=$1", testID)
			cleanupConn.Close()
		}
		conn.Close()
	})

	firstVersion := model.Vulnerability{
		ID:          testID,
		Title:       "Test Vulnerability",
		Description: "This is a test vulnerability",
		Source:      "Testlevel",
		Date:        "2024-06-01",
		ThreatIndex: 50,
	}
	err = UpsertVulnerability(ctx, conn, firstVersion)
	if err != nil {
		t.Fatalf("Failed to upsert first vulnerability: %v", err)
	}

	updatedVersion := firstVersion
	updatedVersion.Title = "Updated Test Vulnerability"
	updatedVersion.Description = "This is an updated test vulnerability"
	updatedVersion.ThreatIndex = 75
	err = UpsertVulnerability(ctx, conn, updatedVersion)
	if err != nil {
		t.Fatalf("Failed to upsert updated vulnerability: %v", err)
	}
	result, err := QueryVulnerabilities(ctx, conn, url.Values{
		"search": []string{testID},
	})
	if err != nil {
		t.Fatalf("Failed to query vulnerabilities: %v", err)
	}
	if len(result) == 0 {
		t.Fatalf("Expected to find at least one vulnerability")
	}
	if result[0].Title != "Updated Test Vulnerability" {
		t.Fatalf("Expected Title %q, got %q", "Updated Test Vulnerability", result[0].Title)
	}
	if result[0].ThreatIndex != 75 {
		t.Fatalf("Expected ThreatIndex 75, got %.2f", result[0].ThreatIndex)
	}
}
