package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/asadQ-dev/threat-shield/internal/db"
	"github.com/asadQ-dev/threat-shield/internal/model"
	"github.com/asadQ-dev/threat-shield/internal/scoring"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Vulnerability = model.Vulnerability

const dateLayout = "2006-01-02"

func ingestThreat(w http.ResponseWriter, r *http.Request, conn *pgxpool.Pool, scorer *scoring.ThreatScorer) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var vulns []Vulnerability
	err := json.NewDecoder(r.Body).Decode(&vulns)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, vuln := range vulns {
		threatIndex := scorer.EvaluateVulnerability(vuln)
		vuln.ThreatIndex = threatIndex
		if err := db.UpsertVulnerability(context.Background(), conn, vuln); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = db.RecordHistory(context.Background(), conn, vuln)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte("Data received by Go engine"))
}

func getVulnerabilities(w http.ResponseWriter, r *http.Request, conn *pgxpool.Pool) {
	vulns, err := db.QueryVulnerabilities(r.Context(), conn, r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(vulns)
}

func getDashboard(w http.ResponseWriter, r *http.Request, conn *pgxpool.Pool) {
	queryParams := r.URL.Query()
	sortVal := queryParams.Get("sort")
	if sortVal == "" {
		queryParams.Set("sort", "threat_index")
	}
	limitValue := queryParams.Get("limit")
	if limitValue == "" {
		limitVal := "40"
		queryParams.Set("limit", limitVal)
	}
	limit, err := strconv.Atoi(queryParams.Get("limit"))
	if err != nil || limit <= 0 {
		http.Error(w, "Invalid limit value", http.StatusBadRequest)
		return
	}
	page := 1
	pageValue := queryParams.Get("page")
	if pageValue != "" {
		page, err = strconv.Atoi(pageValue)
		if err != nil || page < 1 {
			http.Error(w, "Invalid page value", http.StatusBadRequest)
			return
		}
	}
	queryParams.Set("limit", strconv.Itoa(limit+1))
	queryParams.Set("offset", strconv.Itoa((page-1)*limit))
	vulns, err := db.QueryVulnerabilities(r.Context(), conn, queryParams)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hasNext := len(vulns) > limit
	if hasNext {
		vulns = vulns[:limit]
	}

	totalCount := len(vulns)
	var highestThreatIndex float64
	var ransomwareCount int

	for _, v := range vulns {
		if v.ThreatIndex > highestThreatIndex {
			highestThreatIndex = v.ThreatIndex
		}
		if strings.EqualFold(v.RansomwareUse, "Known") || (v.RansomwareUse != "Unknown" && v.RansomwareUse != "" && v.RansomwareUse != "None") {
			ransomwareCount++
		}
	}
	averageScore := 0.0
	if totalCount > 0 {
		var totalScore float64
		for _, v := range vulns {
			totalScore += v.ThreatIndex
		}
		averageScore = totalScore / float64(totalCount)
	}

	renderTemplate(w, "dashboard", map[string]interface{}{
		"Title":              "Threat Dashboard",
		"Vulnerabilities":    vulns,
		"Search":             queryParams.Get("search"),
		"MinScore":           queryParams.Get("min_score"),
		"Sort":               queryParams.Get("sort"),
		"Limit":              strconv.Itoa(limit),
		"TotalCount":         totalCount,
		"HighestThreatIndex": highestThreatIndex,
		"AverageScore":       averageScore,
		"RansomwareCount":    ransomwareCount,
		"Page":               page,
		"HasPrevious":        page > 1,
		"HasNext":            hasNext,
		"PreviousURL":        dashboardPageURL(queryParams, page-1, limit),
		"NextURL":            dashboardPageURL(queryParams, page+1, limit),
	})
}

func dashboardPageURL(queryParams url.Values, page, limit int) string {
	pageParams := url.Values{}
	for key, values := range queryParams {
		if key != "offset" && key != "page" && key != "limit" {
			pageParams[key] = append([]string(nil), values...)
		}
	}
	pageParams.Set("page", strconv.Itoa(page))
	pageParams.Set("limit", strconv.Itoa(limit))
	return "/?" + pageParams.Encode()
}

func getVulnerability(w http.ResponseWriter, r *http.Request, conn *pgxpool.Pool) {
	cveID := strings.TrimPrefix(r.URL.Path, "/vulnerabilities/")
	if cveID == "" {
		http.NotFound(w, r)
		return
	}

	var vuln Vulnerability
	err := conn.QueryRow(context.Background(),
		"SELECT cve_id, title, description, source, COALESCE(date::text, ''), ransomware_use, COALESCE(due_date::text, ''), threat_index FROM vulnerabilities WHERE cve_id = $1",
		cveID,
	).Scan(&vuln.ID, &vuln.Title, &vuln.Description, &vuln.Source, &vuln.Date, &vuln.RansomwareUse, &vuln.DueDate, &vuln.ThreatIndex)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "detail", map[string]interface{}{
		"Title":          vuln.ID,
		"Vulnerability":  vuln,
		"DueDateUrgency": dueDateUrgency(vuln.DueDate),
	})
}

func dueDateUrgency(dueDate string) string {
	due, err := time.Parse(dateLayout, dueDate)
	if err != nil {
		return ""
	}
	daysUntilDue := int(time.Until(due).Hours() / 24)
	switch {
	case daysUntilDue < 0:
		return "Urgency-RED"
	case daysUntilDue <= 7:
		return "Urgency-ORANGE"
	case daysUntilDue <= 14:
		return "Urgency-YELLOW"
	default:
		return ""
	}
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	parsedTemplate, err := template.New("layout.html").Funcs(template.FuncMap{
		"add": func(left, right int) int {
			return left + right
		},
		"dueDateUrgency": dueDateUrgency,
	}).ParseFiles(
		"templates/layout.html",
		fmt.Sprintf("templates/%s.html", tmpl),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = parsedTemplate.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
