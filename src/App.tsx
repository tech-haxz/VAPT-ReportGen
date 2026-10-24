import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowUpRight,
  BookOpen,
  BriefcaseBusiness,
  Check,
  ChevronDown,
  ClipboardList,
  Clock3,
  FilePlus2,
  FileText,
  Filter,
  FolderKanban,
  LayoutDashboard,
  LogOut,
  MoreHorizontal,
  Plus,
  Search,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Trash2,
  UploadCloud,
  X,
} from "lucide-react";
const api = async (path: string, init?: RequestInit) => {
  const r = await fetch(path, {
    ...init,
    headers: {
      ...(init?.headers || {}),
      ...(init?.body instanceof FormData
        ? {}
        : { "Content-Type": "application/json" }),
    },
  });
  if (!r.ok) {
    if (r.status === 401 && path != "/api/auth/me")
      window.dispatchEvent(new Event("auth-expired"));
    let detail = "Request failed";
    try {
      detail = (await r.json()).detail || detail;
    } catch {}
    throw new Error(detail);
  }
  return r.status === 204 ? null : r.json();
};
type Assessment = {
  id: string;
  title: string;
  client?: string;
  kind: string;
  target: string;
  environment: string;
  tester: string;
  finding_count: number;
  scope?: string;
  notes?: string;
};
type Finding = {
  id: string;
  finding_code: string;
  title: string;
  location: string;
  description: string;
  evidence: string;
  severity: string;
  status: string;
  category?: string;
  reviewed: boolean;
  excluded: boolean;
  remediation?: string;
  reproduction?: string;
  impact?: string;
  severity_rationale?: string;
  cvss_assessment?: string;
  root_cause?: string;
  implementation_guidance?: string;
  validation?: string;
  references_text?: string;
  cvss?: string;
  cwe?: string;
  cve?: string;
  component?: string;
  method?: string;
  notes?: string;
  remediation_status?: string;
  evidence_files?: any[];
  ai_json?: string | null;
  updated?: string;
};
const sev = ["Critical", "High", "Medium", "Low", "Informational"];
const findingStatuses = ["Draft", "Open", "In Progress", "Resolved", "Closed"];
const blankFinding = {
  title: "",
  location: "",
  description: "",
  evidence: "",
  severity: "Medium",
  status: "Draft",
  remediation_status: "Open",
  category: "",
  cwe: "",
  cve: "",
  cvss: "",
  component: "",
  method: "",
  reproduction: "",
  expected: "",
  actual: "",
  impact: "",
  severity_rationale: "",
  cvss_assessment: "",
  root_cause: "",
  controls: "",
  remediation: "",
  implementation_guidance: "",
  validation: "",
  references_text: "",
  notes: "",
  reviewed: false,
  excluded: false,
};
export default function App() {
  const [page, setPage] = useState("Overview"),
    [dash, setDash] = useState<any>({
      projects: 0,
      findings: 0,
      severity: {},
      reports: [],
    }),
    [assessments, setAssessments] = useState<Assessment[]>([]),
    [active, setActive] = useState<Assessment | null>(null),
    [findings, setFindings] = useState<Finding[]>([]),
    [selected, setSelected] = useState<Finding | null>(null),
    [form, setForm] = useState<any>(blankFinding),
    [newAssess, setNewAssess] = useState(false),
    [edit, setEdit] = useState(false),
    [search, setSearch] = useState(""),
    [filter, setFilter] = useState("All severities"),
    [health, setHealth] = useState<any>({}),
    [notice, setNotice] = useState(""),
    [reports, setReports] = useState<any[]>([]),
    [templates, setTemplates] = useState<any[]>([]),
    [uploadFiles, setUploadFiles] = useState<File[]>([]),
    [analysis, setAnalysis] = useState<any>(null),
    [busy, setBusy] = useState(false),
    [view, setView] = useState<"findings" | "review">("findings"),
    [auth, setAuth] = useState<any>(null);
  const refresh = async () => {
    try {
      const [d, a, h, r, t] = await Promise.all([
        api("/api/dashboard"),
        api("/api/assessments"),
        api("/api/health"),
        api("/api/reports"),
        api("/api/templates"),
      ]);
      setDash(d);
      setAssessments(a);
      setHealth(h);
      setReports(r);
      setTemplates(t);
      if (active) {
        const fresh = a.find((x: Assessment) => x.id === active.id);
        if (fresh) setActive(fresh);
        setFindings(await api(`/api/assessments/${active.id}/findings`));
      }
    } catch (e: any) {
      setNotice(e.message);
    }
  };
  useEffect(() => {
    const expired = () =>
      setAuth({ authenticated: false, setup_required: false, username: null });
    window.addEventListener("auth-expired", expired);
    api("/api/auth/me")
      .then((a) => {
        setAuth(a);
        if (a.authenticated) refresh();
      })
      .catch(() =>
        setAuth({
          authenticated: false,
          setup_required: false,
          username: null,
        }),
      );
    return () => window.removeEventListener("auth-expired", expired);
  }, []);
  useEffect(() => {
    if (notice) {
      const x = setTimeout(() => setNotice(""), 4000);
      return () => clearTimeout(x);
    }
  }, [notice]);
  const signOut = async () => {
    try {
      await api("/api/auth/logout", { method: "POST" });
      setAuth({ authenticated: false, setup_required: false, username: null });
      setActive(null);
      setFindings([]);
    } catch (e: any) {
      setNotice(e.message);
    }
  };
  const openAssessment = async (a: Assessment) => {
    setActive(a);
    setPage("Findings");
    setView("findings");
    setFindings(await api(`/api/assessments/${a.id}/findings`));
    setSelected(null);
  };
  const filtered = useMemo(
    () =>
      findings.filter(
        (f) =>
          (filter === "All severities" || f.severity === filter) &&
          (!search ||
            `${f.title} ${f.location} ${f.category}`
              .toLowerCase()
              .includes(search.toLowerCase())),
      ),
    [findings, filter, search],
  );
  const newFinding = () => {
    setSelected(null);
    setForm({ ...blankFinding });
    setAnalysis(null);
    setUploadFiles([]);
    setEdit(true);
  };
  const editFinding = (f: Finding) => {
    setSelected(f);
    setForm({ ...f });
    setAnalysis(f.ai_json ? JSON.parse(f.ai_json) : null);
    setUploadFiles([]);
    setEdit(true);
  };
  const saveFinding = async () => {
    try {
      if (!active) throw new Error("Select an assessment first");
      setBusy(true);
      let saved = selected
        ? await api(`/api/findings/${selected.id}`, {
            method: "PUT",
            body: JSON.stringify(form),
          })
        : await api(`/api/assessments/${active.id}/findings`, {
            method: "POST",
            body: JSON.stringify(form),
          });
      setSelected(saved);
      setForm({ ...saved });
      let pending = [...uploadFiles];
      for (const file of [...uploadFiles]) {
        const fd = new FormData();
        fd.append("file", file);
        fd.append("caption", file.name);
        await api(`/api/findings/${saved.id}/evidence`, {
          method: "POST",
          body: fd,
        });
        pending.shift();
        setUploadFiles([...pending]);
      }
      setNotice("Finding saved");
      setEdit(false);
      setUploadFiles([]);
      await openAssessment(active);
      await refresh();
    } catch (e: any) {
      setNotice(e.message);
    } finally {
      setBusy(false);
    }
  };
  const createAssessment = async (e: any) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const data = Object.fromEntries(fd.entries());
    try {
      const a = await api("/api/assessments", {
        method: "POST",
        body: JSON.stringify(data),
      });
      setNewAssess(false);
      await refresh();
      await openAssessment(a);
      setNotice("Assessment created");
    } catch (x: any) {
      setNotice(x.message);
    }
  };
  const deleteFinding = async (f: Finding) => {
    if (!confirm(`Delete ${f.finding_code} — ${f.title}?`)) return;
    await api(`/api/findings/${f.id}`, { method: "DELETE" });
    setNotice("Finding deleted");
    await openAssessment(active!);
    await refresh();
  };
  const deleteAssessment = async (a: Assessment) => {
    if (
      !confirm(
        `Delete assessment "${a.title}" and all of its findings, evidence, and saved reports? This cannot be undone.`,
      )
    )
      return;
    try {
      await api(`/api/assessments/${a.id}`, { method: "DELETE" });
      if (active?.id === a.id) {
        setActive(null);
        setFindings([]);
        setSelected(null);
        setPage("Assessments");
      }
      const [d, as, r] = await Promise.all([
        api("/api/dashboard"),
        api("/api/assessments"),
        api("/api/reports"),
      ]);
      setDash(d);
      setAssessments(as);
      setReports(r);
      setNotice("Assessment and its associated data deleted");
    } catch (e: any) {
      setNotice(e.message);
    }
  };
  const doAnalyze = async () => {
    if (!selected) {
      setNotice("Save the finding before AI analysis");
      return;
    }
    setBusy(true);
    try {
      const r = await api(`/api/findings/${selected.id}/analyze`, {
        method: "POST",
      });
      if (!r.available) {
        setNotice(r.message);
        return;
      }
      setAnalysis(r.analysis);
      setNotice("AI draft generated. Review and edit before saving.");
    } catch (e: any) {
      setNotice(e.message);
    } finally {
      setBusy(false);
    }
  };
  const useAnalysis = () => {
    if (!analysis) return;
    setForm((f: any) => ({
      ...f,
      title: analysis.title || f.title,
      description: analysis.description || f.description,
      evidence: analysis.evidence_summary || f.evidence,
      reproduction: analysis.reproduction || f.reproduction,
      impact: analysis.impact || f.impact,
      severity_rationale: analysis.severity_rationale || f.severity_rationale,
      cvss_assessment: analysis.cvss_assessment || f.cvss_assessment,
      root_cause: analysis.root_cause || f.root_cause,
      implementation_guidance:
        analysis.implementation_guidance || f.implementation_guidance,
      remediation: analysis.remediation || f.remediation,
      validation: analysis.validation || f.validation,
      references_text: analysis.references || f.references_text,
    }));
    setAnalysis(null);
  };
  const downloadReport = async (path: string, filename: string) => {
    const response = await fetch(path);
    if (!response.ok) {
      let message = "Unable to download report";
      try {
        message = (await response.json()).detail || message;
      } catch {}
      throw new Error(message);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const exportReport = async (
    kind = "consolidated",
    include_drafts = false,
  ) => {
    if (!active) return;
    try {
      const r = await api(`/api/assessments/${active.id}/reports`, {
        method: "POST",
        body: JSON.stringify({ kind, include_drafts }),
      });
      await downloadReport(r.download, r.filename);
      setNotice(
        `Report v${r.version} generated (${r.included_findings} findings)`,
      );
      await refresh();
    } catch (e: any) {
      setNotice(e.message);
    }
  };
  const downloadSavedReport = async (r: any) => {
    try {
      await downloadReport(r.download, r.filename);
    } catch (e: any) {
      setNotice(e.message);
    }
  };
  const deleteReport = async (r: any) => {
    if (!confirm(`Delete report ${r.filename}? This cannot be undone.`)) return;
    try {
      await api(`/api/reports/${r.id}`, { method: "DELETE" });
      setReports(await api("/api/reports"));
      setDash(await api("/api/dashboard"));
      setNotice("Report deleted");
    } catch (e: any) {
      setNotice(e.message);
    }
  };
  const upload = async (f: Finding, files: FileList | null) => {
    if (!files) return;
    for (const file of Array.from(files)) {
      const d = new FormData();
      d.append("file", file);
      d.append("caption", "");
      await api(`/api/findings/${f.id}/evidence`, { method: "POST", body: d });
    }
    setNotice("Evidence uploaded");
    await openAssessment(active!);
  };
  const toggleReview = async (f: Finding) => {
    const payload = { ...f, reviewed: !f.reviewed };
    await api(`/api/findings/${f.id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    await openAssessment(active!);
  };
  if (auth === null)
    return <div className="auth-loading">Checking secure session…</div>;
  if (!auth.authenticated)
    return (
      <AuthGate
        setupRequired={auth.setup_required}
        onAuthenticated={(a: any) => {
          setAuth(a);
          refresh();
        }}
      />
    );
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brandmark">
            <Shield size={20} />
          </div>
          <div>
            <b>
              VAPT-ReportGen
            </b>
            <small>REPORTING TOOL</small>
          </div>
        </div>
        <div className="workspace">
          <span className="workspace-dot" />
          LOCAL WORKSPACE
          <ChevronDown size={14} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {[
            [LayoutDashboard, "Overview"],
            [FolderKanban, "Assessments"],
            [ShieldAlert, "Findings"],
            [FileText, "Reports"],
            [BookOpen, "Library"],
          ].map(([Icon, label]: any) => (
            <button
              key={label}
              title={label}
              aria-label={label}
              className={`nav-item ${page === label ? "active" : ""}`}
              onClick={() => {
                setPage(label);
                if (label === "Findings" && !active) setPage("Assessments");
              }}
            >
              <Icon size={17} />
              {label}
              {label === "Findings" && <em>{dash.findings}</em>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="ai-card">
            <div className="ai-head">
              <span
                className={`pulse ${health.ai_configured ? "green" : ""}`}
              />
              <b>AI ENGINE</b>
              <span>{health.ai_configured ? "READY" : "MANUAL"}</span>
            </div>
            <p>
              {health.ai_configured
                ? "Provider connected. Findings stay local until you request analysis."
                : "Manual mode active. Configure a provider to enable AI drafting."}
            </p>
            <button
              onClick={() =>
                setNotice(
                  "Set LLM_API_KEY, LLM_MODEL, and optional LLM_API_URL in backend environment, then restart.",
                )
              }
            >
              Configure <ArrowUpRight size={13} />
            </button>
          </div>
          <div className="user">
            <div className="avatar">
              {String(auth.username || "VT")
                .slice(0, 2)
                .toUpperCase()}
            </div>
            <div>
              <b>{auth.username}</b>
              <small>Secure local account</small>
            </div>
            <button
              className="iconbtn logout-btn"
              title="Log out"
              aria-label="Log out"
              onClick={signOut}
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="crumb">
            Workspace <span>/</span> <b>{page}</b>
            {active && (
              <>
                <span>/</span>
                <b>{active.title}</b>
              </>
            )}
          </div>
          <div className="top-actions">
            <div className="secure">
              <span />
              LOCAL & SECURE
            </div>
            <button className="iconbtn" title="Activity">
              <Activity size={17} />
            </button>
            <div className="avatar small">VT</div>
          </div>
        </header>
        <div className="content">
          {page === "Overview" && (
            <>
              <div className="hero">
                <div>
                  <div className="eyebrow">
                    <span className="eyebrow-line" /> SECURITY ASSESSMENT
                    WORKSPACE
                  </div>
                  <h1>
                    Good morning, <i>Tester.</i>
                  </h1>
                  <p>Here’s the current state of your assessment workspace.</p>
                </div>
                <button
                  className="btn primary"
                  onClick={() => setNewAssess(true)}
                >
                  <Plus size={16} /> New assessment
                </button>
              </div>
              <section className="stats">
                <Stat
                  icon={BriefcaseBusiness}
                  label="Active assessments"
                  value={dash.projects}
                  trend="Independent project spaces"
                />
                <Stat
                  icon={ShieldAlert}
                  label="Total findings"
                  value={dash.findings}
                  trend="Across all assessments"
                />
                <div className="stat-card severity-stat">
                  <div className="stat-top">
                    <span className="stat-icon">
                      <Activity size={16} />
                    </span>
                    <span className="stat-label">SEVERITY DISTRIBUTION</span>
                    <MoreHorizontal size={16} />
                  </div>
                  <div className="severity-bars">
                    {sev.map((s) => (
                      <div key={s}>
                        <span>{s}</span>
                        <div className="bar">
                          <i
                            className={"bar-" + s.toLowerCase()}
                            style={{
                              width: `${dash.findings ? Math.max(3, ((dash.severity[s] || 0) / dash.findings) * 100) : 0}%`,
                            }}
                          />
                        </div>
                        <b>{dash.severity[s] || 0}</b>
                      </div>
                    ))}
                  </div>
                </div>
                <Stat
                  icon={FileText}
                  label="Reports generated"
                  value={reports.length}
                  trend="Versioned exports"
                />
              </section>
              <div className="section-head">
                <div>
                  <h2>Recent assessments</h2>
                  <p>Pick up where you left off.</p>
                </div>
                <button
                  className="text-btn"
                  onClick={() => setPage("Assessments")}
                >
                  View all assessments <ArrowUpRight size={15} />
                </button>
              </div>
              <div className="assessment-grid">
                {assessments.slice(0, 3).map((a) => (
                  <AssessmentCard
                    key={a.id}
                    a={a}
                    open={() => openAssessment(a)}
                    onDelete={deleteAssessment}
                  />
                ))}
                <button className="new-card" onClick={() => setNewAssess(true)}>
                  <span>
                    <Plus size={18} />
                  </span>
                  <b>Create a new assessment</b>
                  <small>Set up a client, scope and target</small>
                </button>
              </div>
              <div className="section-head report-title">
                <div>
                  <h2>Recent reports</h2>
                  <p>Generated documents, ready to review.</p>
                </div>
                <button className="text-btn" onClick={() => setPage("Reports")}>
                  All reports <ArrowUpRight size={15} />
                </button>
              </div>
              <div className="report-list">
                {reports.slice(0, 4).map((r: any) => (
                  <div className="report-row" key={r.id}>
                    <div className="doc-icon">
                      <FileText size={17} />
                    </div>
                    <div className="report-name">
                      <b>{r.filename}</b>
                      <small>
                        {r.assessment_title} · v{r.version}
                      </small>
                    </div>
                    <span className="report-date">
                      {new Date(r.created).toLocaleDateString()}
                    </span>
                    <button
                      className="download"
                      type="button"
                      aria-label={`Download ${r.filename}`}
                      onClick={() => downloadSavedReport(r)}
                    >
                      <ArrowDownToLine size={16} />
                    </button>
                    <button
                      className="delete-report"
                      type="button"
                      aria-label={`Delete ${r.filename}`}
                      title="Delete report"
                      onClick={() => deleteReport(r)}
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                ))}
                {reports.length === 0 && (
                  <div className="empty-inline">No reports generated yet.</div>
                )}
              </div>
            </>
          )}
          {page === "Assessments" && (
            <>
              <div className="page-title">
                <div>
                  <div className="eyebrow">PROJECT MANAGEMENT</div>
                  <h1>Assessments</h1>
                  <p>
                    Manage authorized testing engagements and their findings.
                  </p>
                </div>
                <button
                  className="btn primary"
                  onClick={() => setNewAssess(true)}
                >
                  <Plus size={16} /> New assessment
                </button>
              </div>
              <div className="assessment-grid full-grid">
                {assessments.map((a) => (
                  <AssessmentCard
                    key={a.id}
                    a={a}
                    open={() => openAssessment(a)}
                    onDelete={deleteAssessment}
                  />
                ))}
                {assessments.length === 0 && (
                  <div className="empty-state">
                    No assessments yet. Create one to start documenting
                    findings.
                  </div>
                )}
              </div>
            </>
          )}
          {page === "Findings" && (
            <>
              <div className="page-title">
                <div>
                  <div className="eyebrow">
                    {active?.title || "SELECT AN ASSESSMENT"}
                  </div>
                  <h1>Finding register</h1>
                  <p>
                    Document, review and export evidence-backed vulnerabilities.
                  </p>
                </div>
                <div className="actions">
                  <button
                    className="btn outline"
                    onClick={() =>
                      setView(view === "review" ? "findings" : "review")
                    }
                  >
                    <ClipboardList size={16} />
                    {view === "review" ? "Finding list" : "Review & export"}
                  </button>
                  <button
                    className="btn primary"
                    disabled={!active}
                    onClick={newFinding}
                  >
                    <Plus size={16} /> Add finding
                  </button>
                </div>
              </div>
              {!active ? (
                <div className="empty-state">
                  Choose an assessment to view its findings.{" "}
                  <button
                    className="text-btn"
                    onClick={() => setPage("Assessments")}
                  >
                    Browse assessments
                  </button>
                </div>
              ) : view === "review" ? (
                <Review
                  findings={findings}
                  onToggle={toggleReview}
                  onExport={exportReport}
                />
              ) : (
                <>
                  <div className="toolbar">
                    <div className="searchbox">
                      <Search size={16} />
                      <input
                        placeholder="Search findings, locations..."
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                      />
                      <kbd>⌘ K</kbd>
                    </div>
                    <div className="filter-select">
                      <Filter size={15} />
                      <select
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                      >
                        <option>All severities</option>
                        {sev.map((s) => (
                          <option key={s}>{s}</option>
                        ))}
                      </select>
                      <SlidersHorizontal size={15} />
                    </div>
                    <div className="result-count">
                      {filtered.length} FINDINGS
                    </div>
                  </div>
                  <div className="finding-table">
                    <div className="table-head">
                      <span>FINDING</span>
                      <span>SEVERITY</span>
                      <span>STATUS</span>
                      <span>REMEDIATION</span>
                      <span>UPDATED</span>
                      <span />
                    </div>
                    {filtered.map((f) => (
                      <div className="finding-row" key={f.id}>
                        <button
                          className="finding-main"
                          onClick={() => editFinding(f)}
                        >
                          <div
                            className={`severity-mark ${f.severity.toLowerCase()}`}
                          />
                          <div>
                            <b>{f.title}</b>
                            <small>
                              {f.finding_code} <i>·</i> {f.location}
                            </small>
                          </div>
                        </button>
                        <span>
                          <Badge value={f.severity} />
                        </span>
                        <span>
                          <Status value={f.status} />
                        </span>
                        <span className="plain-status">
                          {f.remediation_status || "Open"}
                        </span>
                        <span className="date-cell">
                          {new Date(
                            f.updated || Date.now(),
                          ).toLocaleDateString()}
                        </span>
                        <div className="row-actions">
                          <button
                            title="Review"
                            onClick={() => toggleReview(f)}
                          >
                            {f.reviewed ? (
                              <Check size={15} />
                            ) : (
                              <ClipboardList size={15} />
                            )}
                          </button>
                          <button
                            title="Duplicate"
                            onClick={async () => {
                              await api(`/api/findings/${f.id}/duplicate`, {
                                method: "POST",
                              });
                              await openAssessment(active);
                              await refresh();
                            }}
                          >
                            ＋
                          </button>
                          <button
                            title="Delete"
                            onClick={() => deleteFinding(f)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </div>
                    ))}
                    {filtered.length === 0 && (
                      <div className="empty-inline">
                        No findings match. Add a finding to this assessment.
                      </div>
                    )}
                  </div>
                </>
              )}
            </>
          )}
          {page === "Reports" && (
            <>
              <div className="page-title">
                <div>
                  <div className="eyebrow">DOCUMENT ARCHIVE</div>
                  <h1>Reports</h1>
                  <p>Versioned Word exports from your assessments.</p>
                </div>
              </div>
              <div className="report-list full-list">
                {reports.map((r: any) => (
                  <div className="report-row" key={r.id}>
                    <div className="doc-icon">
                      <FileText size={17} />
                    </div>
                    <div className="report-name">
                      <b>{r.filename}</b>
                      <small>
                        {r.assessment_title} · {r.kind} · v{r.version}
                      </small>
                    </div>
                    <span className="report-date">
                      {new Date(r.created).toLocaleString()}
                    </span>
                    <button
                      className="download"
                      type="button"
                      aria-label={`Download ${r.filename}`}
                      onClick={() => downloadSavedReport(r)}
                    >
                      <ArrowDownToLine size={16} />
                    </button>
                    <button
                      className="delete-report"
                      type="button"
                      aria-label={`Delete ${r.filename}`}
                      title="Delete report"
                      onClick={() => deleteReport(r)}
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                ))}
                {reports.length === 0 && (
                  <div className="empty-state">
                    No reports yet. Review findings and export a Word document.
                  </div>
                )}
              </div>
            </>
          )}
          {page === "Library" && (
            <>
              <div className="page-title">
                <div>
                  <div className="eyebrow">REUSABLE KNOWLEDGE</div>
                  <h1>Finding library</h1>
                  <p>
                    Approved remediation patterns to reuse without carrying over
                    evidence.
                  </p>
                </div>
                <button
                  className="btn primary"
                  onClick={async () => {
                    const title = prompt("Template title");
                    if (!title) return;
                    await api("/api/templates", {
                      method: "POST",
                      body: JSON.stringify({ title }),
                    });
                    setTemplates(await api("/api/templates"));
                    setNotice("Template saved");
                  }}
                >
                  <Plus size={16} /> New template
                </button>
              </div>
              <div className="library-grid">
                {templates.map((t: any) => (
                  <article className="template-card" key={t.id}>
                    <div className="template-icon">
                      <BookOpen size={18} />
                    </div>
                    <span className="template-tag">
                      {t.category || "GENERAL"}
                    </span>
                    <h3>{t.title}</h3>
                    <p>
                      {t.description ||
                        "Reusable guidance template. Evidence is never copied into a new finding."}
                    </p>
                    <button
                      className="text-btn"
                      onClick={() =>
                        setNotice(
                          "Template editing is available through its saved remediation fields.",
                        )
                      }
                    >
                      View template <ArrowUpRight size={14} />
                    </button>
                  </article>
                ))}
                {templates.length === 0 && (
                  <div className="empty-state">
                    Your finding library is empty. Save approved remediation
                    guidance as a reusable template.
                  </div>
                )}
              </div>
            </>
          )}
        </div>
        <footer className="app-footer">Made by Vinay - VAPT Engineer</footer>
      </main>
      {notice && (
        <div className="toast">
          <span className="toast-dot" />
          {notice}
          <button onClick={() => setNotice("")}>
            <X size={15} />
          </button>
        </div>
      )}
      {newAssess && (
        <div
          className="overlay"
          onMouseDown={(e) =>
            e.target === e.currentTarget && setNewAssess(false)
          }
        >
          <form className="modal" onSubmit={createAssessment}>
            <div className="modal-head">
              <div>
                <div className="eyebrow">NEW WORKSPACE</div>
                <h2>Create assessment</h2>
                <p>Define the authorized engagement scope.</p>
              </div>
              <button
                type="button"
                className="iconbtn"
                onClick={() => setNewAssess(false)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="form-grid">
              <Field
                name="title"
                label="Assessment title *"
                required
                placeholder="e.g. Q3 Web Application Review"
              />
              <Field
                name="client"
                label="Client / organization"
                placeholder="Optional or anonymized"
              />
              <Field
                name="kind"
                label="Assessment type"
                select={[
                  "VAPT",
                  "Web application",
                  "Network",
                  "API",
                  "Email server",
                  "Other",
                ]}
              />
              <Field
                name="environment"
                label="Environment"
                select={["Production", "Staging", "Development", "Lab"]}
              />
              <Field
                name="target"
                label="Target application / host"
                placeholder="app.example.test"
              />
              <Field
                name="tester"
                label="Tester / team"
                placeholder="Team name"
              />
              <Field name="start_date" label="Start date" type="date" />
              <Field name="end_date" label="End date" type="date" />
              <Field
                name="scope"
                label="Scope and authorized boundaries"
                area
              />
              <Field name="notes" label="Assessment notes" area />
            </div>
            <div className="modal-actions">
              <button
                type="button"
                className="btn outline"
                onClick={() => setNewAssess(false)}
              >
                Cancel
              </button>
              <button className="btn primary">
                <Plus size={15} /> Create assessment
              </button>
            </div>
          </form>
        </div>
      )}
      {edit && (
        <div
          className="overlay"
          onMouseDown={(e) => e.target === e.currentTarget && setEdit(false)}
        >
          <div className="drawer">
            <div className="drawer-head">
              <div>
                <div className="eyebrow">
                  {selected ? selected.finding_code : "NEW FINDING"} ·{" "}
                  {active?.title}
                </div>
                <h2>{selected ? "Edit finding" : "Document a finding"}</h2>
                <p>
                  Preserve observed facts. AI suggestions remain editable
                  drafts.
                </p>
              </div>
              <button className="iconbtn" onClick={() => setEdit(false)}>
                <X size={18} />
              </button>
            </div>
            <div className="drawer-body">
              <div className="input-section">
                <div className="form-grid">
                  <Field
                    name="location"
                    label="Vulnerable location, parameter, path, link *"
                    value={form.location}
                    onChange={(v) => setForm({ ...form, location: v })}
                    placeholder="Full URL, parameter, file path, or endpoint"
                    required
                  />
                  <Field
                    name="title"
                    label="Name of the vulnerability *"
                    value={form.title}
                    onChange={(v) => setForm({ ...form, title: v })}
                    placeholder="Vulnerability name"
                    required
                  />
                  <Field
                    name="severity"
                    label="Severity *"
                    value={form.severity || "Medium"}
                    onChange={(v) => setForm({ ...form, severity: v })}
                    select={sev}
                    required
                  />
                  <Field
                    name="status"
                    label="Status"
                    value={form.status || "Draft"}
                    onChange={(v) => setForm({ ...form, status: v })}
                    select={findingStatuses}
                  />
                  <Field
                    name="references_text"
                    label="References (CVE-ID, CWE-ID, Bugtraq-ID, etc.)"
                    value={form.references_text}
                    onChange={(v) => setForm({ ...form, references_text: v })}
                    placeholder="Add IDs or reference links"
                    area
                  />
                  <Field
                    name="method"
                    label="Tools, scripts, frameworks used"
                    value={form.method}
                    onChange={(v) => setForm({ ...form, method: v })}
                    placeholder="e.g. tool and version, script, or framework"
                    area
                  />
                  <Field
                    name="evidence"
                    label="Proof of concept / observed evidence *"
                    value={form.evidence}
                    onChange={(v) => setForm({ ...form, evidence: v })}
                    placeholder="Record the observed proof. Keep exact responses and values."
                    area
                    required
                  />
                  <Field
                    name="reproduction"
                    label="Steps of verification"
                    value={form.reproduction}
                    onChange={(v) => setForm({ ...form, reproduction: v })}
                    placeholder="List only steps supported by your test observations."
                    area
                  />
                </div>
              </div>
              <section className="evidence-section">
                <div className="subhead">
                  <div>
                    <h3>Evidence & screenshots</h3>
                    <p>
                      Original files are stored separately with SHA-256
                      integrity identifiers.
                    </p>
                  </div>
                </div>
                {selected &&
                  selected.evidence_files &&
                  selected.evidence_files.length > 0 && (
                    <div className="evidence-thumbs">
                      {selected!.evidence_files!.map((x: any) => (
                        <div className="evidence-thumb" key={x.id}>
                          <img src={`/api/evidence/${x.id}`} alt={x.filename} />
                          <div>
                            <b>{x.filename}</b>
                            <small>SHA-256 · {x.sha256.slice(0, 14)}…</small>
                            <button
                              onClick={async () => {
                                await api(`/api/evidence/${x.id}`, {
                                  method: "DELETE",
                                });
                                setSelected(
                                  await api(`/api/findings/${selected!.id}`),
                                );
                              }}
                            >
                              Remove
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                <label
                  className="dropzone"
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    setUploadFiles(Array.from(e.dataTransfer.files || []));
                  }}
                >
                  <input
                    type="file"
                    multiple
                    accept="image/png,image/jpeg,image/webp"
                    onChange={(e) =>
                      setUploadFiles(Array.from(e.target.files || []))
                    }
                  />
                  <UploadCloud size={22} />
                  <b>Drop screenshots here or browse</b>
                  <small>PNG, JPG, WebP · up to 12 MB each</small>
                  {uploadFiles.length > 0 && (
                    <span>{uploadFiles.map((x) => x.name).join(", ")}</span>
                  )}
                </label>
              </section>
              <section className="ai-section">
                <div className="ai-banner">
                  <span>
                    <Sparkles size={16} />
                  </span>
                  <div>
                    <b>AI finding analysis</b>
                    <small>
                      {health.ai_configured
                        ? "Grounded drafting. Your request sends finding text to the configured provider."
                        : "Manual mode — configure a server provider to enable drafting."}
                    </small>
                  </div>
                  <button
                    className="btn outline"
                    disabled={!health.ai_configured || busy || !selected}
                    onClick={doAnalyze}
                  >
                    {busy ? "Analyzing…" : "Generate draft"}
                  </button>
                </div>
                {analysis && (
                  <div className="analysis-box">
                    <div className="analysis-head">
                      <b>AI-generated draft · review required</b>
                      <button className="text-btn" onClick={useAnalysis}>
                        Apply to editable fields <ArrowUpRight size={14} />
                      </button>
                    </div>
                    <div className="analysis-grid">
                      {Object.entries(analysis)
                        .slice(0, 8)
                        .map(([k, v]) => (
                          <div key={k}>
                            <b>{k.replace(/_/g, " ")}</b>
                            <p>
                              {typeof v === "string" ? v : JSON.stringify(v)}
                            </p>
                          </div>
                        ))}
                    </div>
                  </div>
                )}
              </section>
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={form.reviewed}
                  onChange={(e) =>
                    setForm({ ...form, reviewed: e.target.checked })
                  }
                />{" "}
                Mark as reviewed and eligible for standard export
              </label>
            </div>
            <div className="drawer-foot">
              <button className="btn outline" onClick={() => setEdit(false)}>
                Cancel
              </button>
              <button
                className="btn primary"
                onClick={saveFinding}
                disabled={busy}
              >
                <Check size={15} />
                {busy ? "Saving…" : "Save finding"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function AuthGate({
  setupRequired,
  onAuthenticated,
}: {
  setupRequired: boolean;
  onAuthenticated: (auth: any) => void;
}) {
  const [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const submit = async (e: any) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const auth = await api(
        setupRequired ? "/api/auth/signup" : "/api/auth/login",
        { method: "POST", body: JSON.stringify({ username, password }) },
      );
      onAuthenticated(auth);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <main className="auth-screen">
      <form className="auth-card" onSubmit={submit}>
        <div className="auth-brand">
          <span>
            <Shield size={20} />
          </span>
          <div>
            <b>
              VAPT-ReportGen
            </b>
            <small>SECURE LOCAL WORKSPACE</small>
          </div>
        </div>
        <div className="eyebrow">
          {setupRequired ? "FIRST-TIME SETUP" : "ACCOUNT SECURITY"}
        </div>
        <h1>{setupRequired ? "Create your account" : "Welcome back"}</h1>
        <p>
          {setupRequired
            ? "Create a password to protect this local assessment workspace. This installation has one account."
            : "Log in to access your assessments and reports."}
        </p>
        {error && (
          <div className="auth-error" role="alert">
            {error}
          </div>
        )}
        <label className="field">
          <span>Username</span>
          <input
            autoComplete="username"
            autoFocus
            required
            minLength={3}
            maxLength={64}
            pattern="[A-Za-z0-9_.-]+"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="3–64 letters, numbers, . _ -"
          />
        </label>
        <label className="field">
          <span>Password</span>
          <input
            autoComplete={setupRequired ? "new-password" : "current-password"}
            type="password"
            required
            minLength={12}
            maxLength={256}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="At least 12 characters"
          />
        </label>
        {setupRequired && (
          <small className="password-hint">
            Use at least 12 characters. The password is stored as a salted hash.
          </small>
        )}
        <button className="btn primary auth-submit" disabled={busy}>
          {busy
            ? setupRequired
              ? "Creating account…"
              : "Logging in…"
            : setupRequired
              ? "Create account"
              : "Log in"}
        </button>
        <div className="auth-lock">
          <ShieldAlert size={14} /> Session cookie is HttpOnly and expires after
          8 hours.
        </div>
      </form>
    </main>
  );
}
function Stat({ icon: Icon, label, value, trend }: any) {
  return (
    <div className="stat-card">
      <div className="stat-top">
        <span className="stat-icon">
          <Icon size={16} />
        </span>
        <span className="stat-label">{label.toUpperCase()}</span>
        <MoreHorizontal size={16} />
      </div>
      <div className="stat-value">
        {value}
        <small>{trend}</small>
      </div>
    </div>
  );
}
function AssessmentCard({ a, open, onDelete }: any) {
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <article className="assessment-card">
      <div className="card-top">
        <button className="assessment-card-top-button" onClick={open}>
          <span className="app-icon">
            <Shield size={16} />
          </span>
          <span className="environment">{a.environment || "Lab"}</span>
        </button>
        <div className="assessment-menu-wrap">
          <button
            type="button"
            className="card-menu-button"
            aria-label={`Options for ${a.title}`}
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen(!menuOpen)}
          >
            <MoreHorizontal size={17} />
          </button>
          {menuOpen && (
            <div className="assessment-menu" role="menu">
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setMenuOpen(false);
                  onDelete(a);
                }}
              >
                <Trash2 size={14} /> Delete assessment
              </button>
            </div>
          )}
        </div>
      </div>
      <button className="assessment-card-open" onClick={open}>
        <h3>{a.title}</h3>
        <p>{a.target || "Target not specified"}</p>
        <div className="card-meta">
          <span>
            <BriefcaseBusiness size={13} />
            {a.kind}
          </span>
          <span>
            <ShieldAlert size={13} />
            {a.finding_count} findings
          </span>
        </div>
        <div className="card-footer">
          <span className="client">
            <i />
            {a.client || "Internal / anonymized"}
          </span>
          <span>
            OPEN <ArrowUpRight size={13} />
          </span>
        </div>
      </button>
    </article>
  );
}
function Badge({ value }: any) {
  return (
    <span className={"badge " + String(value).toLowerCase().replace(" ", "-")}>
      {value}
    </span>
  );
}
function Status({ value }: any) {
  return (
    <span
      className={
        "status status-" + String(value).toLowerCase().replace(" ", "-")
      }
    >
      <i />
      {value}
    </span>
  );
}
function Field({
  name,
  label,
  value,
  onChange,
  placeholder,
  type = "text",
  select,
  area,
  required,
}: {
  name: string;
  label: string;
  value?: string;
  onChange?: (value: string) => void;
  placeholder?: string;
  type?: string;
  select?: string[];
  area?: boolean;
  required?: boolean;
}) {
  return (
    <label className={`field ${area ? "span-2" : ""}`}>
      <span>{label}</span>
      {select ? (
        <select
          name={name}
          value={value}
          required={required}
          onChange={(e) => (onChange ? onChange(e.target.value) : null)}
        >
          {select.map((x: string) => (
            <option key={x}>{x}</option>
          ))}
        </select>
      ) : area ? (
        <textarea
          name={name}
          value={value}
          required={required}
          placeholder={placeholder}
          onChange={(e) => (onChange ? onChange(e.target.value) : null)}
          rows={3}
        />
      ) : (
        <input
          name={name}
          type={type}
          value={value}
          required={required}
          placeholder={placeholder}
          onChange={(e) => (onChange ? onChange(e.target.value) : null)}
        />
      )}
    </label>
  );
}
function Review({ findings, onToggle, onExport }: any) {
  let n = findings.filter((f: Finding) => !f.reviewed && !f.excluded).length;
  return (
    <div className="review-layout">
      <div className="review-checklist">
        <div className="review-icon">
          <ClipboardList size={19} />
        </div>
        <h2>Export readiness</h2>
        <p>
          Review findings and check the report before creating an editable Word
          document.
        </p>
        <div className="check-item">
          <span className={n === 0 ? "check-ok" : ""}>
            {n === 0 ? <Check size={14} /> : n}
          </span>
          <div>
            <b>
              {n === 0
                ? "All findings reviewed"
                : `${n} finding${n === 1 ? "" : "s"} need review`}
            </b>
            <small>Standard exports include reviewed findings only.</small>
          </div>
        </div>
        <div className="check-item">
          <span>
            {findings.filter((f: Finding) => !f.remediation?.trim()).length}
          </span>
          <div>
            <b>Remediation sections to complete</b>
            <small>
              Empty remediation will be visible in the finding form.
            </small>
          </div>
        </div>
        <div className="check-item">
          <span>
            {findings.filter((f: Finding) => !f.evidence?.trim()).length}
          </span>
          <div>
            <b>Findings missing technical evidence</b>
            <small>Provide observed evidence before final distribution.</small>
          </div>
        </div>
        <div className="review-actions">
          <button
            className="btn primary"
            onClick={() => onExport("consolidated", false)}
          >
            <FileText size={15} /> Export reviewed findings
          </button>
          <button
            className="btn outline"
            onClick={() => onExport("detailed", true)}
          >
            <FilePlus2 size={15} /> Include drafts clearly labeled
          </button>
        </div>
        <small className="review-note">
          Exports are versioned. Your saved edits and original evidence remain
          unchanged.
        </small>
      </div>
      <div className="review-list">
        <div className="subhead">
          <div>
            <h3>Finding review</h3>
            <p>Toggle individual findings as reviewed.</p>
          </div>
          <span>{findings.length} TOTAL</span>
        </div>
        {findings.map((f: Finding) => (
          <div className="review-row" key={f.id}>
            <div className={`severity-mark ${f.severity.toLowerCase()}`} />
            <div>
              <b>
                {f.finding_code} · {f.title}
              </b>
              <small>{f.location}</small>
            </div>
            <Badge value={f.severity} />
            <button
              className={f.reviewed ? "reviewed-btn" : "review-btn"}
              onClick={() => onToggle(f)}
            >
              {f.reviewed ? (
                <>
                  <Check size={14} /> Reviewed
                </>
              ) : (
                "Mark reviewed"
              )}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
