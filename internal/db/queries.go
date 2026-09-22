package db

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/asadQ-dev/threat-shield/internal/alert"
	"github.com/asadQ-dev/threat-shield/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

func QueryVulnerabilities(ctx context.Context, conn *pgxpool.Pool, queryParams url.Values) ([]model.Vulnerability, error) {
	baseQuery := "SELECT cve_id, title, description, source, COALESCE(date::text, ''), ransomware_use, COALESCE(due_date::text, ''), threat_index FROM vulnerabilities"
	var conditions []string
	var args []interface{}
	argCounter := 1

	minScore := queryParams.Get("min_score")
	if minScore != "" {
		threshold, err := strconv.ParseFloat(minScore, 64)
		if err != nil || threshold < 0 || threshold > 100 {
			return nil, fmt.Errorf("invalid min_score value (must be between 0 and 100)")
		}
		conditions = append(conditions, fmt.Sprintf("threat_index >= $%d", argCounter))
		args = append(args, threshold)
		argCounter++
	}

	searchQuery := queryParams.Get("search")
	if searchQuery != "" {
		conditions = append(conditions, fmt.Sprintf("(cve_id ILIKE $%d OR title ILIKE $%d OR description ILIKE $%d)", argCounter, argCounter, argCounter))
		args = append(args, "%"+searchQuery+"%")
		argCounter++
	}
	if len(conditions) > 0 {
		baseQuery += " WHERE " + strings.Join(conditions, " AND ")
	}

	sortBy := queryParams.Get("sort")
	if sortBy == "" {
		sortBy = "threat_index"
	}
	switch sortBy {
	case "threat_index", "threatIndex":
		baseQuery += " ORDER BY threat_index DESC, cve_id DESC"
	case "cve_id", "cveId":
		baseQuery += " ORDER BY cve_id ASC"
	case "due_date_asc":
		baseQuery += " ORDER BY due_date ASC, cve_id ASC"
	case "due_date_desc":
		baseQuery += " ORDER BY due_date DESC, cve_id DESC"
	default:
		return nil, fmt.Errorf("invalid sort parameter")
	}

	if limitStr := queryParams.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 {
			return nil, fmt.Errorf("invalid limit value (must be a non-negative integer)")
		}
		baseQuery += fmt.Sprintf(" LIMIT $%d", argCounter)
		args = append(args, limit)
		argCounter++
	}
	if offsetStr := queryParams.Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			return nil, fmt.Errorf("invalid offset value (must be a non-negative integer)")
		}
		baseQuery += fmt.Sprintf(" OFFSET $%d", argCounter)
		args = append(args, offset)
	}

	rows, err := conn.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	vulnerabilities := make([]model.Vulnerability, 0)
	for rows.Next() {
		var vuln model.Vulnerability
		if err := rows.Scan(&vuln.ID, &vuln.Title, &vuln.Description, &vuln.Source, &vuln.Date, &vuln.RansomwareUse, &vuln.DueDate, &vuln.ThreatIndex); err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	return vulnerabilities, rows.Err()
}

func UpsertVulnerability(ctx context.Context, conn *pgxpool.Pool, vuln model.Vulnerability) error {
	query := `
		INSERT INTO vulnerabilities (cve_id, title, description, source, date, ransomware_use, due_date, threat_index)
		VALUES ($1, $2, $3, $4, NULLIF($5, '')::date, $6, NULLIF($7, '')::date, $8)
		ON CONFLICT (cve_id) DO UPDATE SET 
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			source = EXCLUDED.source,
			date = EXCLUDED.date,
			ransomware_use = EXCLUDED.ransomware_use,
			due_date = EXCLUDED.due_date,
			threat_index = EXCLUDED.threat_index
		RETURNING (xmax = 0) AS inserted
	`
	var inserted bool
	err := conn.QueryRow(ctx, query, vuln.ID, vuln.Title, vuln.Description, vuln.Source, vuln.Date, vuln.RansomwareUse, vuln.DueDate, vuln.ThreatIndex).Scan(&inserted)
	if err != nil {
		return err
	}
	if inserted {
		if err := alert.SendNewVulnerabilityAlert(vuln); err != nil {
			log.Printf("Failed to send new vulnerability alert for %s: %v", vuln.ID, err)
		}
	}
	return nil
}
