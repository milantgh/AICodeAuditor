package aiaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuleSetCompiles(t *testing.T) {
	rules, version, err := Catalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	if version == "" || len(rules) < 20 {
		t.Fatalf("unexpected catalog: version=%q rules=%d", version, len(rules))
	}
	if _, err := NewScanner(DefaultOptions()); err != nil {
		t.Fatalf("compile: %v", err)
	}
}

func TestScanDetectsAISecurityIssues(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"app/llm.py": `import openai
from langchain.llms import OpenAI

client = openai.OpenAI(api_key="sk-proj-abcdefghijklmnopqrstuvwxyz123456")

def handle(request):
    prompt = f"user said: {request.args['q']}"
    completion = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])
    eval(completion.choices[0].message.content)
    torch.load("./model.bin")
    return prompt
`,
		"app/agent.js":     "const messages = `system: ${req.body.question}`;\nconst x = dangerous.innerHTML = completion;\n",
		"requirements.txt": "openai==1.0.0\nlangchain==0.2.0\ntorch==2.3.0\n",
		".env":             "OPENAI_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz\n",
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Test fixtures must be skipped by default.
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "fixture.py"), []byte(`eval(response)`), 0o644); err != nil {
		t.Fatal(err)
	}

	scanner, err := NewScanner(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	report, err := scanner.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.ScannedFiles < 4 {
		t.Fatalf("scanned %d files, want >= 4", report.ScannedFiles)
	}
	ids := map[string]bool{}
	for _, f := range report.Findings {
		ids[f.RuleID] = true
		if f.File == "tests/fixture.py" {
			t.Fatalf("test fixture should be skipped: %+v", f)
		}
	}
	for _, want := range []string{"AIC-001", "AIC-003", "AIC-004", "AIC-007", "AIC-008", "AIC-018"} {
		if !ids[want] {
			t.Errorf("missing rule %s in findings: %+v", want, ids)
		}
	}
	if report.Summary.Total != len(report.Findings) {
		t.Fatalf("summary total %d != findings %d", report.Summary.Total, len(report.Findings))
	}
	if report.RiskScore == 0 || report.Grade == "" {
		t.Fatalf("risk not computed: %d %q", report.RiskScore, report.Grade)
	}

	names := map[string]bool{}
	for _, c := range report.Components {
		names[c.Name] = true
	}
	for _, want := range []string{"OpenAI SDK", "LangChain", "PyTorch"} {
		if !names[want] {
			t.Errorf("missing component %s: %+v", want, names)
		}
	}
}

func TestScanHandlesCleanProject(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	scanner, err := NewScanner(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	report, err := scanner.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Total != 0 || report.Grade != "A" {
		t.Fatalf("expected clean report, got %+v", report.Summary)
	}
}
