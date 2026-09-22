package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/asadQ-dev/threat-shield/internal/db"
	"github.com/asadQ-dev/threat-shield/internal/scoring"
)

func TestCollectData(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vulnerabilityName": "Fake Test Vulnerability",
                    "shortDescription": "A test vulnerability for unit testing",
                    "dateAdded": "2024-01-01",
                    "knownRansomwareCampaignUse": "Unknown",
                    "dueDate": "2024-01-15"
                }
            ]
        }`))
	}))
	defer fakeServer.Close()
	ctx := context.Background()
	conn, err := db.Connect(ctx)
	if err != nil {
		t.Fatalf("Failed to connect to the database: %v", err)
	}
	defer conn.Close()
	threat_scorer := scoring.ThreatScorer{
		BaseIndex:     50,
		ScalingScalar: 1.5,
		FallbackHits:  10,
	}

	err = CollectData(ctx, conn, &threat_scorer, fakeServer.URL)
	if err != nil {
		t.Fatalf("Failed to collect data: %v", err)
	}
}

func TestCollectDataBadStatus(t *testing.T) {
	fakeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer fakeServer.Close()
	err := CollectData(context.Background(), nil, nil, fakeServer.URL)
	if err == nil {
		t.Fatalf("Expected error due to bad status code, got nil")
	}
}
