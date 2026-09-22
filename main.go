package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/asadQ-dev/threat-shield/internal/auth"
	"github.com/asadQ-dev/threat-shield/internal/collector"
	"github.com/asadQ-dev/threat-shield/internal/db"
	"github.com/asadQ-dev/threat-shield/internal/scoring"
	"github.com/asadQ-dev/threat-shield/internal/worker"

	"github.com/joho/godotenv"
)

func main() {
	scorer := scoring.ThreatScorer{
		BaseIndex:     23.17,
		ScalingScalar: 46.08,
		FallbackHits:  15.0,
	}
	fmt.Println("Threat Pipeline active on port 8080... Waiting for data.")
	err := godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found. Using existing environment variables.")
	}
	conn, err := db.Connect(context.Background())
	if err != nil {
		fmt.Println("Failed to connect to the database:", err)
		return
	}
	defer conn.Close()
	schedulerCtx, stopScheduler := context.WithCancel(context.Background())
	worker.StartBackgroundCollector(schedulerCtx, 10*time.Minute, func(ctx context.Context) error {
		if err := collector.CollectData(ctx, conn, &scorer, collector.KEV_URL); err != nil {
			fmt.Println("Failed to collect data:", err)
			return err
		}
		return nil
	})

	http.Handle("/api/vulnerabilities", auth.RequireAPIKey(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getVulnerabilities(w, r, conn)
			return
		}
		ingestThreat(w, r, conn, &scorer)
	})))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		getDashboard(w, r, conn)
	})
	http.HandleFunc("/vulnerabilities/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		getVulnerability(w, r, conn)
	})
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	srv := &http.Server{
		Addr:    ":8080",
		Handler: nil,
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Println("Failed to start server:", err)
		}
	}()

	<-stop
	fmt.Println("Shutting down server...")
	stopScheduler()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		fmt.Println("Server forced to shutdown:", err)
	}
}
