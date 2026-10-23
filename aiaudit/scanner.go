package aiaudit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Options controls the static scan boundaries.
type Options struct {
	// IncludeTests also scans test fixtures. Off by default: fixtures often
	// contain intentionally fake keys and dominate the report.
	IncludeTests bool
	// MaxFileBytes skips larger files (vendor bundles, datasets, logs).
	MaxFileBytes int64
	// MaxFiles caps how many files are read in one run.
	MaxFiles int
	// MaxFindings caps the report size; the scan stops cleanly when reached.
	MaxFindings int
}

// DefaultOptions returns conservative production defaults.
func DefaultOptions() Options {
	return Options{
		IncludeTests: false,
		MaxFileBytes: 1024 * 1024,
		MaxFiles:     20000,
		MaxFindings:  2000,
	}
}

func (o Options) normalized() Options {
	d := DefaultOptions()
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = d.MaxFileBytes
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = d.MaxFiles
	}
	if o.MaxFindings <= 0 {
		o.MaxFindings = d.MaxFindings
	}
	return o
}

// Finding is one rule hit at a concrete file:line location.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Snippet     string   `json:"snippet"`
	Matched     string   `json:"matched"`
}

// Component is an AI framework / model service detected in the project.
type Component struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Evidence    string `json:"evidence"`
	Occurrences int    `json:"occurrences"`
}

// Summary aggregates findings for dashboards.
type Summary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
}

// Report is the complete output of one scan.
type Report struct {
	Root           string      `json:"root"`
	TaskID         string      `json:"task_id,omitempty"`
	EngineVersion  string      `json:"engine_version"`
	RuleVersion    string      `json:"rule_version"`
	GeneratedAt    string      `json:"generated_at"`
	DurationMS     int64       `json:"duration_ms"`
	ScannedFiles   int         `json:"scanned_files"`
	SkippedFiles   int         `json:"skipped_files"`
	ScannedBytes   int64       `json:"scanned_bytes"`
	RulesEvaluated int         `json:"rules_evaluated"`
	Findings       []Finding   `json:"findings"`
	Summary        Summary     `json:"summary"`
	Components     []Component `json:"components"`
	RiskScore      int         `json:"risk_score"`
	Grade          string      `json:"grade"`
	Truncated      bool        `json:"truncated"`
}

// Scanner is a compiled, reusable rule engine.
type Scanner struct {
	rules       []compiledRule
	ruleVersion string
	opts        Options
}

// NewScanner compiles the embedded rule set.
func NewScanner(opts Options) (*Scanner, error) {
	rules, version, err := compileRuleSet()
	if err != nil {
		return nil, err
	}
	return &Scanner{rules: rules, ruleVersion: version, opts: opts.normalized()}, nil
}

// ScanDir walks root and returns a deterministic report. It never follows
// symlinks and never leaves the given directory.
func (s *Scanner) ScanDir(root string) (*Report, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("源码目录不可读: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("不是目录: %s", root)
	}

	started := time.Now()
	report := &Report{
		Root:           filepath.ToSlash(absRoot),
		EngineVersion:  engineVersion,
		RuleVersion:    s.ruleVersion,
		GeneratedAt:    started.UTC().Format(time.RFC3339),
		RulesEvaluated: len(s.rules),
		Findings:       []Finding{},
		Components:     []Component{},
	}
	components := map[string]*Component{}

	walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entries are counted and skipped, never fatal: an audit
			// should still report what it could read.
			report.SkippedFiles++
			return nil
		}
		if d.IsDir() {
			if path != absRoot && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, relErr := filepath.Rel(absRoot, path)
		if relErr != nil {
			report.SkippedFiles++
			return nil
		}
		rel = filepath.ToSlash(rel)
		base := d.Name()

		info, statErr := d.Info()
		if statErr != nil {
			report.SkippedFiles++
			return nil
		}
		if !s.scannable(rel, base, info.Size()) {
			report.SkippedFiles++
			return nil
		}
		if report.ScannedFiles >= s.opts.MaxFiles {
			report.Truncated = true
			return fs.SkipAll
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil || int64(len(data)) > s.opts.MaxFileBytes {
			report.SkippedFiles++
			return nil
		}
		if isBinary(data) {
			report.SkippedFiles++
			return nil
		}

		report.ScannedFiles++
		report.ScannedBytes += int64(len(data))
		text := string(data)

		findings := s.scanText(rel, base, text)
		if remaining := s.opts.MaxFindings - len(report.Findings); remaining > 0 {
			if len(findings) > remaining {
				findings = findings[:remaining]
				report.Truncated = true
			}
			report.Findings = append(report.Findings, findings...)
		} else if len(findings) > 0 {
			report.Truncated = true
			return fs.SkipAll
		}

		collectComponents(text, rel, base, components)
		return nil
	})
	if walkErr != nil && walkErr != fs.SkipAll {
		return nil, walkErr
	}

	sortFindings(report.Findings)
	report.Summary = summarize(report.Findings)
	report.Components = sortComponents(components)
	report.RiskScore, report.Grade = risk(report.Summary)
	report.DurationMS = time.Since(started).Milliseconds()
	return report, nil
}

func (s *Scanner) scanText(rel, base, text string) []Finding {
	lines := strings.Split(text, "\n")
	fileExt := ruleExtension(base)
	var out []Finding
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		if len(line) > 4096 {
			line = line[:4096]
		}
		for _, cr := range s.rules {
			if !ruleMatchesFile(cr.rule, fileExt) {
				continue
			}
			if cr.negative != nil && cr.negative.MatchString(line) {
				continue
			}
			for _, re := range cr.patterns {
				loc := re.FindStringIndex(line)
				if loc == nil {
					continue
				}
				out = append(out, Finding{
					RuleID:      cr.rule.ID,
					Title:       cr.rule.Title,
					Severity:    cr.rule.Severity,
					Category:    cr.rule.Category,
					Description: cr.rule.Description,
					Remediation: cr.rule.Remediation,
					References:  cr.rule.References,
					File:        rel,
					Line:        i + 1,
					Column:      loc[0] + 1,
					Snippet:     clip(strings.TrimSpace(line), 240),
					Matched:     clip(strings.TrimSpace(line[loc[0]:loc[1]]), 120),
				})
				break
			}
		}
	}
	return out
}

func (s *Scanner) scannable(rel, base string, size int64) bool {
	if size <= 0 || size > s.opts.MaxFileBytes {
		return false
	}
	lower := strings.ToLower(base)
	if _, skip := skipFiles[lower]; skip {
		return false
	}
	if strings.HasSuffix(lower, ".min.js") || strings.HasSuffix(lower, ".map") {
		return false
	}
	if !s.opts.IncludeTests && isTestFile(rel, lower) {
		return false
	}
	if isEnvFile(lower) {
		return true
	}
	if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(lower))
	switch ext {
	case ".md":
		return strings.EqualFold(base, "SKILL.md")
	case ".txt":
		return strings.HasPrefix(lower, "requirements")
	case ".xml":
		return lower == "pom.xml"
	case ".go", ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
		".java", ".kt", ".kts", ".rb", ".php", ".rs", ".cs", ".swift", ".c", ".h",
		".cc", ".cpp", ".cxx", ".hpp", ".sh", ".bash", ".zsh", ".ps1", ".yml",
		".yaml", ".json", ".jsonc", ".toml", ".ini", ".cfg", ".conf", ".properties",
		".sql", ".tf", ".gradle":
		return true
	}
	return false
}

func ruleExtension(base string) string {
	lower := strings.ToLower(base)
	if isEnvFile(lower) {
		return ".env"
	}
	return strings.ToLower(filepath.Ext(lower))
}

func ruleMatchesFile(r Rule, ext string) bool {
	if len(r.Extensions) == 0 {
		return true
	}
	for _, allowed := range r.Extensions {
		if strings.EqualFold(allowed, ext) {
			return true
		}
	}
	return false
}

func isEnvFile(lowerBase string) bool {
	return lowerBase == ".env" || strings.HasPrefix(lowerBase, ".env.")
}

func isBinary(data []byte) bool {
	limit := len(data)
	if limit > 512 {
		limit = 512
	}
	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func isTestFile(rel, lowerBase string) bool {
	relLower := strings.ToLower(filepath.ToSlash(rel))
	for _, marker := range []string{"/test/", "/tests/", "/__tests__/", "/spec/", "/fixtures/", "/testdata/"} {
		if strings.Contains("/"+relLower, marker) {
			return true
		}
	}
	if strings.HasSuffix(lowerBase, "_test.go") ||
		strings.HasPrefix(lowerBase, "test_") ||
		strings.HasSuffix(lowerBase, "_test.py") ||
		strings.Contains(lowerBase, ".test.") ||
		strings.Contains(lowerBase, ".spec.") {
		return true
	}
	return false
}

var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true,
	"third_party": true, "dist": true, "build": true, "out": true, ".next": true,
	"__pycache__": true, ".venv": true, "venv": true, "env": true, "target": true,
	"bin": true, "obj": true, ".idea": true, ".vscode": true, "data": true,
	"logs": true, "coverage": true, ".cache": true, ".pytest_cache": true,
	".mypy_cache": true, "site-packages": true,
}

func skipDir(name string) bool {
	return skipDirs[strings.ToLower(name)]
}

var skipFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.sum": true, "poetry.lock": true, "pipfile.lock": true, "cargo.lock": true,
	"composer.lock": true, "gemfile.lock": true, "license": true, "license.txt": true,
	"license.md": true, "copying": true, "notice": true,
}

func collectComponents(text, rel, base string, into map[string]*Component) {
	manifest := isManifest(base)
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !manifest && !isImportLine(trimmed) {
			continue
		}
		lower := strings.ToLower(trimmed)
		for _, def := range componentCatalog {
			for _, token := range def.Tokens {
				if containsToken(lower, token) {
					c := into[def.Name]
					if c == nil {
						c = &Component{Name: def.Name, Category: def.Category}
						into[def.Name] = c
					}
					c.Occurrences++
					if c.Evidence == "" {
						c.Evidence = rel
					}
					break
				}
			}
		}
	}
}

func isImportLine(line string) bool {
	for _, prefix := range []string{"import ", "from ", "require(", "require ", "#include", "using ", "use "} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func isManifest(base string) bool {
	switch strings.ToLower(base) {
	case "package.json", "requirements.txt", "pyproject.toml", "pipfile", "go.mod",
		"pom.xml", "build.gradle", "build.gradle.kts", "environment.yml", "dockerfile":
		return true
	}
	return false
}

func containsToken(haystack, token string) bool {
	if token == "" {
		return false
	}
	start := 0
	for {
		idx := strings.Index(haystack[start:], token)
		if idx < 0 {
			return false
		}
		idx += start
		beforeOK := idx == 0 || !isIdentChar(haystack[idx-1])
		after := idx + len(token)
		afterOK := after >= len(haystack) || !isIdentChar(haystack[after])
		if beforeOK && afterOK {
			return true
		}
		start = idx + 1
	}
}

func isIdentChar(b byte) bool {
	return b == '_' || b == '-' || b == '.' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	cut := max - 1
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := SeverityRank(findings[i].Severity), SeverityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

func summarize(findings []Finding) Summary {
	sum := Summary{
		Total:      len(findings),
		BySeverity: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
		ByCategory: map[string]int{},
	}
	for _, f := range findings {
		sum.BySeverity[f.Severity]++
		sum.ByCategory[f.Category]++
	}
	return sum
}

func sortComponents(into map[string]*Component) []Component {
	out := make([]Component, 0, len(into))
	for _, c := range into {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func risk(sum Summary) (int, string) {
	score := sum.BySeverity["critical"]*25 + sum.BySeverity["high"]*10 +
		sum.BySeverity["medium"]*4 + sum.BySeverity["low"]
	if score > 100 {
		score = 100
	}
	switch {
	case score == 0:
		return score, "A"
	case score <= 20:
		return score, "B"
	case score <= 45:
		return score, "C"
	case score <= 70:
		return score, "D"
	default:
		return score, "E"
	}
}

type componentDef struct {
	Name     string
	Category string
	Tokens   []string
}

var componentCatalog = []componentDef{
	{Name: "OpenAI SDK", Category: "模型服务", Tokens: []string{"openai"}},
	{Name: "Anthropic SDK", Category: "模型服务", Tokens: []string{"anthropic"}},
	{Name: "Google Gemini", Category: "模型服务", Tokens: []string{"generativeai", "google.generativeai", "gemini"}},
	{Name: "Ollama", Category: "模型服务", Tokens: []string{"ollama"}},
	{Name: "vLLM", Category: "推理引擎", Tokens: []string{"vllm"}},
	{Name: "Transformers", Category: "模型框架", Tokens: []string{"transformers", "huggingface"}},
	{Name: "PyTorch", Category: "模型框架", Tokens: []string{"torch", "pytorch"}},
	{Name: "TensorFlow", Category: "模型框架", Tokens: []string{"tensorflow"}},
	{Name: "LangChain", Category: "编排框架", Tokens: []string{"langchain", "langchain_core", "langchain-openai"}},
	{Name: "LlamaIndex", Category: "编排框架", Tokens: []string{"llama_index", "llama-index", "llamaindex"}},
	{Name: "Haystack", Category: "编排框架", Tokens: []string{"haystack"}},
	{Name: "Semantic Kernel", Category: "编排框架", Tokens: []string{"semantic_kernel", "semantic-kernel"}},
	{Name: "CrewAI", Category: "Agent 框架", Tokens: []string{"crewai"}},
	{Name: "AutoGen", Category: "Agent 框架", Tokens: []string{"autogen", "ag2"}},
	{Name: "MCP", Category: "Agent 框架", Tokens: []string{"modelcontextprotocol", "mcp.server", "mcp_server", "fastmcp"}},
	{Name: "Gradio", Category: "AI 应用框架", Tokens: []string{"gradio"}},
	{Name: "Streamlit", Category: "AI 应用框架", Tokens: []string{"streamlit"}},
	{Name: "Dify", Category: "AI 平台", Tokens: []string{"dify"}},
	{Name: "RAGFlow", Category: "AI 平台", Tokens: []string{"ragflow"}},
	{Name: "Flowise", Category: "AI 平台", Tokens: []string{"flowise"}},
	{Name: "n8n", Category: "AI 平台", Tokens: []string{"n8n"}},
	{Name: "Coze", Category: "AI 平台", Tokens: []string{"coze"}},
	{Name: "Chroma", Category: "向量数据库", Tokens: []string{"chromadb", "chroma"}},
	{Name: "FAISS", Category: "向量数据库", Tokens: []string{"faiss"}},
	{Name: "Pinecone", Category: "向量数据库", Tokens: []string{"pinecone"}},
	{Name: "Qdrant", Category: "向量数据库", Tokens: []string{"qdrant"}},
	{Name: "Milvus", Category: "向量数据库", Tokens: []string{"milvus", "pymilvus"}},
	{Name: "Weaviate", Category: "向量数据库", Tokens: []string{"weaviate"}},
}
