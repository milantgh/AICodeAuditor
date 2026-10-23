// Package aiaudit implements AICodeAuditor's AI code audit engine.
//
// It is a deterministic, static-only analyzer: it reads source files and
// matches a curated rule set focused on LLM/AI application risks (prompt
// injection, model output handling, agent tool abuse, secrets, supply chain,
// RAG/memory poisoning and unsafe model loading). It never executes code,
// never performs network requests and never modifies the scanned tree.
package aiaudit

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const engineVersion = "1.0.0"

//go:embed rules.json
var rulesFS embed.FS

// Rule is one declarative AI code audit rule.
type Rule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
	// Extensions limits the rule to the given file suffixes. Empty means all
	// supported source/config files.
	Extensions []string `json:"extensions,omitempty"`
	// Patterns are Go regular expressions. Any match on a line produces a
	// finding; only the first match of the first matching pattern is kept.
	Patterns []string `json:"patterns"`
	// Negative suppresses the rule when it matches the same line (used to
	// ignore placeholders and safe variants).
	Negative string `json:"negative,omitempty"`
}

// RuleSet is the embedded catalog with compiled patterns.
type RuleSet struct {
	Version string `json:"version"`
	Updated string `json:"updated"`
	Rules   []Rule `json:"rules"`
}

type compiledRule struct {
	rule     Rule
	patterns []*regexp.Regexp
	negative *regexp.Regexp
}

// RuleSetData is the raw embedded catalog (metadata only, no compiled state).
func RuleSetData() (*RuleSet, error) {
	raw, err := rulesFS.ReadFile("rules.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded rules: %w", err)
	}
	var set RuleSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("parse embedded rules: %w", err)
	}
	sort.Slice(set.Rules, func(i, j int) bool { return set.Rules[i].ID < set.Rules[j].ID })
	return &set, nil
}

// Catalog returns the rule metadata shown in the UI (no compiled regexes).
func Catalog() ([]Rule, string, error) {
	set, err := RuleSetData()
	if err != nil {
		return nil, "", err
	}
	return set.Rules, set.Version, nil
}

// compileRuleSet validates and compiles every rule. It fails loudly so a bad
// rule can never silently disable part of the audit.
func compileRuleSet() ([]compiledRule, string, error) {
	set, err := RuleSetData()
	if err != nil {
		return nil, "", err
	}
	seen := map[string]bool{}
	out := make([]compiledRule, 0, len(set.Rules))
	for _, r := range set.Rules {
		if r.ID == "" || r.Title == "" {
			return nil, "", fmt.Errorf("rule without id/title")
		}
		if seen[r.ID] {
			return nil, "", fmt.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if !validSeverity(r.Severity) {
			return nil, "", fmt.Errorf("rule %s has invalid severity %q", r.ID, r.Severity)
		}
		if len(r.Patterns) == 0 {
			return nil, "", fmt.Errorf("rule %s has no patterns", r.ID)
		}
		cr := compiledRule{rule: r}
		for _, p := range r.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, "", fmt.Errorf("rule %s pattern %q: %w", r.ID, p, err)
			}
			cr.patterns = append(cr.patterns, re)
		}
		if strings.TrimSpace(r.Negative) != "" {
			re, err := regexp.Compile(r.Negative)
			if err != nil {
				return nil, "", fmt.Errorf("rule %s negative pattern: %w", r.ID, err)
			}
			cr.negative = re
		}
		out = append(out, cr)
	}
	return out, set.Version, nil
}

func validSeverity(s string) bool {
	switch s {
	case "critical", "high", "medium", "low":
		return true
	}
	return false
}

// SeverityRank orders findings from most to least severe.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

// EngineVersion reports the analyzer version embedded in reports.
func EngineVersion() string { return engineVersion }
