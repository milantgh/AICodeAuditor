"use client";

import * as React from "react";

import {
  AlertTriangleIcon,
  FileSearchIcon,
  Loader2Icon,
  PlayIcon,
  ShieldCheckIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { statusMeta, toneClasses } from "@/lib/status";
import type { AIAuditFinding, AIAuditReport, AIAuditRulesResponse, Task } from "@/lib/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function SeverityBadge({ severity }: { severity: string }) {
  const meta = statusMeta("severity", severity);
  return (
    <span className={`inline-flex items-center rounded-4xl border px-2 py-0.5 text-xs font-medium ${toneClasses[meta.tone]}`}>
      {meta.label}
    </span>
  );
}

function GradeBadge({ grade, risk }: { grade: string; risk: number }) {
  const tone = grade === "A" ? "green" : grade === "B" ? "blue" : grade === "C" ? "amber" : "red";
  return (
    <span className={`inline-flex items-center rounded-lg border px-2.5 py-1 text-sm font-semibold ${toneClasses[tone]}`}>
      {grade} 级 · 风险 {risk}
    </span>
  );
}

export default function AIAuditPage() {
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [taskId, setTaskId] = React.useState("");
  const [includeTests, setIncludeTests] = React.useState(false);
  const [report, setReport] = React.useState<AIAuditReport | null>(null);
  const [loadingReport, setLoadingReport] = React.useState(false);
  const [scanning, setScanning] = React.useState(false);
  const [rules, setRules] = React.useState<AIAuditRulesResponse | null>(null);
  const [severityFilter, setSeverityFilter] = React.useState<string>("");

  React.useEffect(() => {
    api
      .tasks()
      .then((r) => {
        setTasks(r.tasks);
        const first = r.tasks.find((t) => !!t.source_path) ?? r.tasks[0];
        if (first) setTaskId(first.id);
      })
      .catch((e) => toast.error(`读取任务列表失败：${(e as Error).message}`));
    api
      .aiAuditRules()
      .then(setRules)
      .catch((e) => toast.error(`读取规则库失败：${(e as Error).message}`));
  }, []);

  const selected = tasks.find((t) => t.id === taskId);

  React.useEffect(() => {
    if (!taskId) {
      setReport(null);
      return;
    }
    let alive = true;
    setLoadingReport(true);
    api
      .aiAuditReport(taskId)
      .then((r) => {
        // 演示模式（NEXT_PUBLIC_MOCK）下接口返回空对象，按“尚未扫描”处理。
        if (alive) setReport(r && Array.isArray(r.findings) ? r : null);
      })
      .catch(() => {
        // 404 = 该任务尚未扫描过，属于正常情况。
        if (alive) setReport(null);
      })
      .finally(() => {
        if (alive) setLoadingReport(false);
      });
    return () => {
      alive = false;
    };
  }, [taskId]);

  const scan = async () => {
    if (!taskId) {
      toast.error("请先选择任务");
      return;
    }
    if (!selected?.source_path) {
      toast.error("该任务还没有上传源码包，请先在任务详情里上传");
      return;
    }
    setScanning(true);
    try {
      const r = await api.aiAuditScan(taskId, { includeTests });
      setReport(r);
      toast.success(`扫描完成：${r.summary.total} 条命中，${r.scanned_files} 个文件`);
    } catch (e) {
      toast.error(`扫描失败：${(e as Error).message}`);
    } finally {
      setScanning(false);
    }
  };

  const findings = React.useMemo(() => {
    const list = report?.findings ?? [];
    if (!severityFilter) return list;
    return list.filter((f) => f.severity === severityFilter);
  }, [report, severityFilter]);

  return (
    <div className="p-4 md:p-6">
      <div className="mb-4">
        <h1 className="flex items-center gap-2 font-semibold text-xl">
          <ShieldCheckIcon className="size-5" />
          AI 代码审计
        </h1>
        <p className="text-muted-foreground text-sm">
          针对 AI 应用代码的静态安全审计：提示注入、模型输出直通执行、不安全反序列化、密钥硬编码、工具能力过大、记忆投毒等。
          只读源码，不执行代码、不联网。
        </p>
      </div>

      <Card className="mb-4">
        <CardContent className="flex flex-wrap items-end gap-3 py-4">
          <div className="grid gap-1.5">
            <Label htmlFor="ai-audit-task">审计任务</Label>
            <NativeSelect
              id="ai-audit-task"
              className="w-72"
              value={taskId}
              onChange={(e) => setTaskId(e.target.value)}
            >
              {tasks.length === 0 && <NativeSelectOption value="">（暂无可审计任务）</NativeSelectOption>}
              {tasks.map((t) => (
                <NativeSelectOption key={t.id} value={t.id}>
                  {t.name || t.description || `任务 ${t.id}`}
                  {t.source_path ? "" : "（未上传源码）"}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          <label className="flex items-center gap-2 pb-2 text-sm">
            <Checkbox checked={includeTests} onCheckedChange={(c) => setIncludeTests(!!c)} />
            包含测试代码
          </label>
          <Button className="mb-0.5" onClick={scan} disabled={scanning || !taskId}>
            {scanning ? <Loader2Icon className="animate-spin" /> : <PlayIcon />}
            {scanning ? "扫描中…" : "开始审计"}
          </Button>
          {selected && (
            <span className="pb-2 text-muted-foreground text-xs">
              源码目录：{selected.source_path || "未上传"}
            </span>
          )}
        </CardContent>
      </Card>

      <Tabs defaultValue="result">
        <TabsList>
          <TabsTrigger value="result">审计结果</TabsTrigger>
          <TabsTrigger value="rules">规则库{rules ? `（${rules.rules.length}）` : ""}</TabsTrigger>
        </TabsList>

        <TabsContent value="result" className="mt-4">
          {loadingReport ? (
            <Card>
              <CardContent className="flex items-center justify-center gap-2 py-12 text-muted-foreground text-sm">
                <Loader2Icon className="size-4 animate-spin" /> 读取审计结果…
              </CardContent>
            </Card>
          ) : !report ? (
            <Card>
              <CardContent className="flex flex-col items-center gap-2 py-12 text-center">
                <FileSearchIcon className="size-8 text-muted-foreground" />
                <p className="font-medium text-sm">还没有审计结果</p>
                <p className="text-muted-foreground text-xs">选择任务后点击「开始审计」即可生成报告。</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Card>
                  <CardContent className="py-4">
                    <div className="text-muted-foreground text-xs">风险评级</div>
                    <div className="mt-2">
                      <GradeBadge grade={report.grade} risk={report.risk_score} />
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="py-4">
                    <div className="text-muted-foreground text-xs">命中总数</div>
                    <div className="mt-1 font-semibold text-2xl">{report.summary.total}</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {SEVERITY_ORDER.map((s) => {
                        const n = report.summary.by_severity?.[s] ?? 0;
                        if (!n) return null;
                        return (
                          <React.Fragment key={s}>
                            <SeverityBadge severity={s} />
                            <span className="text-muted-foreground text-xs">{n}</span>
                          </React.Fragment>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="py-4">
                    <div className="text-muted-foreground text-xs">扫描规模</div>
                    <div className="mt-1 font-semibold text-2xl">{report.scanned_files}</div>
                    <div className="text-muted-foreground text-xs">
                      文件 · 跳过 {report.skipped_files} · 规则 {report.rules_evaluated} 条 ·{" "}
                      {(report.scanned_bytes / 1024).toFixed(0)} KB
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="py-4">
                    <div className="text-muted-foreground text-xs">引擎 / 规则版本</div>
                    <div className="mt-1 font-medium text-sm">
                      {report.engine_version} / {report.rule_version}
                    </div>
                    <div className="text-muted-foreground text-xs">
                      耗时 {report.duration_ms} ms · {report.generated_at}
                    </div>
                  </CardContent>
                </Card>
              </div>

              {report.components?.length > 0 && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">识别到的 AI 组件</CardTitle>
                  </CardHeader>
                  <CardContent className="flex flex-wrap gap-2">
                    {report.components.map((c) => (
                      <Badge key={`${c.name}-${c.evidence}`} variant="secondary" title={c.evidence}>
                        {c.name} · {c.category}（{c.occurrences}）
                      </Badge>
                    ))}
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
                  <CardTitle className="text-base">命中明细</CardTitle>
                  <div className="flex flex-wrap gap-1">
                    <Button
                      size="sm"
                      variant={severityFilter === "" ? "default" : "outline"}
                      onClick={() => setSeverityFilter("")}
                    >
                      全部 {report.summary.total}
                    </Button>
                    {SEVERITY_ORDER.map((s) => {
                      const n = report.summary.by_severity?.[s] ?? 0;
                      if (!n) return null;
                      return (
                        <Button
                          key={s}
                          size="sm"
                          variant={severityFilter === s ? "default" : "outline"}
                          onClick={() => setSeverityFilter(s)}
                        >
                          {statusMeta("severity", s).label} {n}
                        </Button>
                      );
                    })}
                  </div>
                </CardHeader>
                <CardContent>
                  {report.truncated && (
                    <div className="mb-3 flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-amber-700 text-xs dark:text-amber-400">
                      <AlertTriangleIcon className="size-4" />
                      命中数量超过上限，结果已截断，请缩小审计范围或分目录审计。
                    </div>
                  )}
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-20">级别</TableHead>
                        <TableHead className="w-28">规则</TableHead>
                        <TableHead>位置</TableHead>
                        <TableHead>代码 / 命中内容</TableHead>
                        <TableHead className="w-64">修复建议</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {findings.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                            当前筛选下没有命中。
                          </TableCell>
                        </TableRow>
                      )}
                      {findings.map((f: AIAuditFinding, i) => (
                        <TableRow key={`${f.rule_id}-${f.file}-${f.line}-${i}`}>
                          <TableCell>
                            <SeverityBadge severity={f.severity} />
                          </TableCell>
                          <TableCell>
                            <div className="font-mono text-xs">{f.rule_id}</div>
                            <div className="text-muted-foreground text-xs" title={f.description}>
                              {f.title}
                            </div>
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {f.file}:{f.line}
                          </TableCell>
                          <TableCell>
                            <code className="block max-w-xl truncate rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                              {f.snippet || f.matched}
                            </code>
                          </TableCell>
                          <TableCell className="text-muted-foreground text-xs">{f.remediation}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        <TabsContent value="rules" className="mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base">内置规则库</CardTitle>
              <p className="text-muted-foreground text-xs">
                规则参考 OWASP LLM Top 10 与 OWASP Agentic Security 分类整理，全部为可解释的正则规则。
              </p>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">编号</TableHead>
                    <TableHead className="w-20">级别</TableHead>
                    <TableHead className="w-40">分类</TableHead>
                    <TableHead className="w-64">标题</TableHead>
                    <TableHead>说明</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(rules?.rules ?? []).map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="font-mono text-xs">{r.id}</TableCell>
                      <TableCell>
                        <SeverityBadge severity={r.severity} />
                      </TableCell>
                      <TableCell className="text-xs">{r.category}</TableCell>
                      <TableCell className="text-sm">{r.title}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{r.description}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
