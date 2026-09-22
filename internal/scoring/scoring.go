package scoring

import (
	"math"
	"strings"

	"github.com/asadQ-dev/threat-shield/internal/model"
)

type ThreatScorer struct {
	BaseIndex     float64
	ScalingScalar float64
	FallbackHits  float64
}

func (ts *ThreatScorer) EvaluateVulnerability(vuln model.Vulnerability) float64 {
	rawScore := 0.0
	matched := false
	lowerDesc := strings.ToLower(vuln.Description)
	lowerTitle := strings.ToLower(vuln.Title)
	categories := []struct {
		Points  float64
		Phrases []string
	}{
		{Points: 35.0, Phrases: []string{"remote code execution", "rce", "arbitrary code execution", "execute arbitrary code", "execute arbitrary command", "code execution"}},
		{Points: 30.0, Phrases: []string{"sql injection", "command injection", "deserialization", "unsafe reflection", "code injection", "path traversal", "restricted directory", "server-side request forgery"}},
		{Points: 25.0, Phrases: []string{"privilege escalation", "privileged", "improper privilege management", "privilege management", "embedded malicious code"}},
		{Points: 20.0, Phrases: []string{"stack", "buffer overflow", "out of bounds", "out-of-bounds", "type confusion", "memory corruption", "use-after-free", "memory buffer"}},
		{Points: 15.0, Phrases: []string{"unauth", "missing authentication", "missing authorization", "authentication bypass", "improper authentication", "authorization bypass", "unrestricted upload"}},
		{Points: 12.0, Phrases: []string{"cross-site scripting", "denial of service", "information disclosure"}},
	}
	for _, category := range categories {
		for _, phrase := range category.Phrases {
			if strings.Contains(lowerDesc, phrase) || strings.Contains(lowerTitle, phrase) {
				rawScore += category.Points
				matched = true
				break
			}
		}
	}
	if strings.ToLower(vuln.RansomwareUse) == "known" || strings.Contains(strings.ToLower(vuln.RansomwareUse), "known exploitation") {
		rawScore += 25.0
	}
	if vuln.DueDate != "" {
		rawScore += 10.0
	}
	if !matched && vuln.RansomwareUse == "" && vuln.DueDate == "" {
		rawScore += ts.FallbackHits
	}
	denominator := 1 + math.Exp(-(rawScore-ts.BaseIndex)/ts.ScalingScalar)
	threatIndex := 100.0 / denominator
	return threatIndex
}
