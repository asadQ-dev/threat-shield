package scoring

import (
	"testing"

	"github.com/asadQ-dev/threat-shield/internal/model"
)

func TestEvaluateVulnerability(t *testing.T) {
	scorer := &ThreatScorer{
		BaseIndex:     10.0,
		ScalingScalar: 1.5,
		FallbackHits:  5.0,
	}
	vuln := model.Vulnerability{
		Title:       "Remote Code Execution Vulnerability",
		Description: "This vulnerability allows remote code execution.",
	}
	score := scorer.EvaluateVulnerability(vuln)
	if score <= 0 {
		t.Errorf("Expected positive score, got %f", score)
	}
}
