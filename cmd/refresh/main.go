// Temporary one-off utility to re-run the collector immediately and
// overwrite stale/uncalibrated scores in the DB. Not wired into the server.
package main

import (
	"context"
	"fmt"

	"github.com/asadQ-dev/threat-shield/internal/collector"
	"github.com/asadQ-dev/threat-shield/internal/db"
	"github.com/asadQ-dev/threat-shield/internal/scoring"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	scorer := scoring.ThreatScorer{
		BaseIndex:     23.17,
		ScalingScalar: 46.08,
		FallbackHits:  15.0,
	}
	conn, err := db.Connect(context.Background())
	if err != nil {
		fmt.Println("Failed to connect to the database:", err)
		return
	}
	defer conn.Close()
	if err := collector.CollectData(context.Background(), conn, &scorer, collector.KEV_URL); err != nil {
		fmt.Println("Collection failed:", err)
		return
	}
	fmt.Println("Collection complete.")
}
