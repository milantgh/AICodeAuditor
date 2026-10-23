package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aicodeauditor/aiaudit"
)

// =====================================================================
// AI 代码审计（静态规则引擎）
//
// 接口：
//   GET  /api/ai-audit/rules                  规则目录（引擎内置规则集）
//   POST /api/tasks/{id}/ai-audit/scan        扫描任务源码目录
//   GET  /api/tasks/{id}/ai-audit/report      读取上一次扫描结果
//
// 扫描是纯静态的：只读源码文本、不执行代码、不联网。规则覆盖提示注入、
// 模型输出直通执行、不安全反序列化、密钥硬编码、工具能力过大、SSRF、
// 记忆投毒等 AI 应用常见风险。
// =====================================================================

// aiAuditRelDir 是任务 AI 审计结果的存放目录（相对任务目录）。
const aiAuditRelDir = "ai-audit"

// aiAuditRulesResponse 是 GET /api/ai-audit/rules 的响应。
type aiAuditRulesResponse struct {
	EngineVersion string         `json:"engine_version"`
	RuleVersion   string         `json:"rule_version"`
	Rules         []aiaudit.Rule `json:"rules"`
	Categories    []string       `json:"categories"`
	Severities    []string       `json:"severities"`
}

// GET /api/ai-audit/rules — 返回内置规则目录，供前端展示与筛选。
func (s *Server) aiAuditRules(w http.ResponseWriter, r *http.Request) {
	rules, version, err := aiaudit.Catalog()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	seenCat := map[string]bool{}
	seenSev := map[string]bool{}
	cats := make([]string, 0, 8)
	sevs := make([]string, 0, 5)
	for _, rule := range rules {
		if rule.Category != "" && !seenCat[rule.Category] {
			seenCat[rule.Category] = true
			cats = append(cats, rule.Category)
		}
		if rule.Severity != "" && !seenSev[rule.Severity] {
			seenSev[rule.Severity] = true
			sevs = append(sevs, rule.Severity)
		}
	}
	writeJSON(w, 200, aiAuditRulesResponse{
		EngineVersion: aiaudit.EngineVersion(),
		RuleVersion:   version,
		Rules:         rules,
		Categories:    cats,
		Severities:    sevs,
	})
}

// aiAuditScanRequest 是扫描请求体；所有字段可选。
type aiAuditScanRequest struct {
	IncludeTests bool `json:"include_tests"`
}

func (s *Server) aiAuditReportPath(taskID string) string {
	return filepath.Join(s.m.dir, "tasks", taskID, aiAuditRelDir, "report.json")
}

func (s *Server) loadAIAuditReport(taskID string) (*aiaudit.Report, error) {
	raw, err := os.ReadFile(s.aiAuditReportPath(taskID))
	if err != nil {
		return nil, err
	}
	var rep aiaudit.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// POST /api/tasks/{id}/ai-audit/scan — 扫描任务的源码目录并落盘结果。
//
// 源码目录来自任务上传的源码包（data/tasks/<id>/source）；没有上传过源码时
// 直接返回 409，让用户先上传，避免“扫描了一个空目录还显示 A 级”的误导。
func (s *Server) aiAuditScan(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	srcRel := strings.TrimSpace(t.SourcePath)
	if srcRel == "" {
		writeErr(w, 409, "该任务还没有上传源码包，请先上传后再做 AI 代码审计")
		return
	}
	root := filepath.Join(s.m.dir, filepath.FromSlash(srcRel))
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		writeErr(w, 409, "任务源码目录不存在，可能已被清理")
		return
	}

	var req aiAuditScanRequest
	if r.Body != nil {
		// 空 body 视为默认参数；解析失败也按默认处理，保持接口宽容。
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
	}

	opts := aiaudit.DefaultOptions()
	opts.IncludeTests = req.IncludeTests

	scanner, err := aiaudit.NewScanner(opts)
	if err != nil {
		writeErr(w, 500, "初始化扫描器失败: "+err.Error())
		return
	}
	rep, err := scanner.ScanDir(root)
	if err != nil {
		writeErr(w, 500, "扫描失败: "+err.Error())
		return
	}
	rep.TaskID = t.ID
	// 只回传相对路径，避免把服务端数据目录的绝对路径暴露给前端。
	rep.Root = filepath.ToSlash(srcRel)
	rep.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	if err := s.saveAIAuditReport(t.ID, rep); err != nil {
		// 落盘失败不影响本次结果返回，只是下次 GET 取不到。
		writeJSON(w, 200, map[string]any{"report": rep, "persisted": false, "persist_error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"report": rep, "persisted": true})
}

func (s *Server) saveAIAuditReport(taskID string, rep *aiaudit.Report) error {
	p := s.aiAuditReportPath(taskID)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// GET /api/tasks/{id}/ai-audit/report — 读取上一次扫描结果。
func (s *Server) aiAuditGetReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.m.Task(id); !ok {
		writeErr(w, 404, "task not found")
		return
	}
	rep, err := s.loadAIAuditReport(id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeErr(w, 404, "该任务还没有 AI 代码审计结果")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rep)
}
