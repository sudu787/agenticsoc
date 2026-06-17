"use client";

import { useEffect, useState } from "react";
import { getDashboard, getHealth, getIngestionStatus } from "@/lib/api";
import type { DashboardData, Alert, AgentActivity, SystemHealth } from "@/lib/types";
import { AlertCircle, Target, Ticket, Activity, RefreshCw, Zap, ShieldCheck, Database, PlayCircle } from "lucide-react";

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [health, setHealth] = useState<any>(null);
  const [ingestion, setIngestion] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAll();
    const interval = setInterval(loadAll, 15000);
    return () => clearInterval(interval);
  }, []);

  async function loadAll() {
    try {
      const [dashResult, healthResult, ingestionResult] = await Promise.allSettled([
        getDashboard(),
        getHealth(),
        getIngestionStatus(),
      ]);
      if (dashResult.status === "fulfilled") setData(dashResult.value);
      if (healthResult.status === "fulfilled") setHealth(healthResult.value);
      if (ingestionResult.status === "fulfilled") setIngestion(ingestionResult.value);
    } catch {
      // Backend may not be running
    } finally {
      setLoading(false);
    }
  }

  const stats = data?.stats;
  const riskScore = stats?.risk_score ?? 0;
  const riskLevel = stats?.risk_level ?? "low";

  const riskColor = riskLevel === "critical" ? "#dc2626" : riskLevel === "high" ? "#f97316" : riskLevel === "medium" ? "#eab308" : "#10b981";
  const circumference = 2 * Math.PI * 60;
  const dashArray = `${(riskScore / 100) * circumference} ${circumference}`;

  return (
    <div className="sf-animate-in">
      {/* Page Header */}
      <div className="sf-page-header">
        <div>
          <h1 className="sf-page-title">Security Dashboard</h1>
          <p className="sf-page-subtitle">Real-time security operations overview • SecureFlow AI</p>
        </div>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          {ingestion?.running && (
            <span style={{
              display: "flex", alignItems: "center", gap: "6px",
              background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.3)",
              padding: "4px 12px", borderRadius: "20px", fontSize: "11px",
              color: "#10b981", fontWeight: 600,
            }}>
              <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#10b981", animation: "pulse 2s ease-in-out infinite" }} />
              Live Ingestion
            </span>
          )}
          <button className="sf-btn sf-btn-secondary sf-btn-sm" onClick={loadAll}>
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="sf-stats-grid">
        <div className="sf-stat-card danger">
          <div className="sf-stat-icon"><AlertCircle size={24} color="#ef4444" /></div>
          <div className="sf-stat-label">Open Alerts</div>
          <div className="sf-stat-value">{stats?.open_alerts ?? 0}</div>
          <div className="sf-stat-change up">
            {stats?.critical_alerts ?? 0} critical • {stats?.high_alerts ?? 0} high
          </div>
        </div>

        <div className="sf-stat-card warning">
          <div className="sf-stat-icon"><Target size={24} color="#f59e0b" /></div>
          <div className="sf-stat-label">Open Incidents</div>
          <div className="sf-stat-value">{stats?.open_incidents ?? 0}</div>
          <div className="sf-stat-change" style={{ color: "var(--sf-text-muted)" }}>
            {stats?.total_incidents ?? 0} total
          </div>
        </div>

        <div className="sf-stat-card info">
          <div className="sf-stat-icon"><Ticket size={24} color="#3b82f6" /></div>
          <div className="sf-stat-label">Open Tickets</div>
          <div className="sf-stat-value">{stats?.open_tickets ?? 0}</div>
          <div className="sf-stat-change" style={{ color: "var(--sf-success)" }}>
            {stats?.resolved_tickets ?? 0} resolved
          </div>
        </div>

        <div className="sf-stat-card accent">
          <div className="sf-stat-icon"><Activity size={24} color="#8b5cf6" /></div>
          <div className="sf-stat-label">Events Ingested</div>
          <div className="sf-stat-value">{ingestion?.events_ingested ?? stats?.events_today ?? 0}</div>
          <div className="sf-stat-change" style={{ color: "var(--sf-text-muted)" }}>
            {ingestion?.alerts_created ?? 0} alerts created
          </div>
        </div>

        <div className="sf-stat-card success">
          <div className="sf-stat-icon"><Zap size={24} color="#10b981" /></div>
          <div className="sf-stat-label">AI Actions Today</div>
          <div className="sf-stat-value">{stats?.agent_actions_today ?? 0}</div>
          <div className="sf-stat-change" style={{ color: "var(--sf-text-muted)" }}>
            Autonomous operations
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div className="sf-grid-dashboard">
        {/* Left Column */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Ingestion Pipeline Status */}
          {ingestion && (
            <div className="sf-card" style={{ borderColor: ingestion.running ? "rgba(16,185,129,0.3)" : "var(--sf-border)" }}>
              <div className="sf-card-header">
                <div>
                  <div className="sf-card-title"><Database size={16} style={{ display: 'inline', marginRight: 6, verticalAlign: 'text-bottom' }} /> Automated Ingestion Pipeline</div>
                  <div className="sf-card-subtitle">Real-time log collection → parsing → detection → alerting</div>
                </div>
                <span className={`sf-badge ${ingestion.running ? "open" : "resolved"}`}>
                  {ingestion.running ? "● Running" : "○ Stopped"}
                </span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "16px", padding: "4px 0" }}>
                <div style={{ textAlign: "center" }}>
                  <div style={{ fontSize: "22px", fontWeight: 700, color: "var(--sf-accent-light)" }}>
                    {ingestion.simulator?.lines_written ?? 0}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", marginTop: "2px" }}>Logs Written</div>
                </div>
                <div style={{ textAlign: "center" }}>
                  <div style={{ fontSize: "22px", fontWeight: 700, color: "#10b981" }}>
                    {ingestion.events_ingested}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", marginTop: "2px" }}>Events Parsed</div>
                </div>
                <div style={{ textAlign: "center" }}>
                  <div style={{ fontSize: "22px", fontWeight: 700, color: "#f97316" }}>
                    {ingestion.simulator?.attack_events ?? 0}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", marginTop: "2px" }}>Threats Simulated</div>
                </div>
                <div style={{ textAlign: "center" }}>
                  <div style={{ fontSize: "22px", fontWeight: 700, color: "#dc2626" }}>
                    {ingestion.alerts_created}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", marginTop: "2px" }}>Alerts Created</div>
                </div>
              </div>
              {ingestion.last_ingestion && (
                <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", marginTop: "8px", textAlign: "right" }}>
                  Last ingestion: {new Date(ingestion.last_ingestion).toLocaleTimeString()} • {ingestion.errors} errors
                </div>
              )}
            </div>
          )}

          {/* Recent Alerts */}
          <div className="sf-card">
            <div className="sf-card-header">
              <div>
                <div className="sf-card-title"><AlertCircle size={16} style={{ display: 'inline', marginRight: 6, verticalAlign: 'text-bottom' }} /> Recent Security Alerts</div>
                <div className="sf-card-subtitle">Latest detected threats — auto-generated by ingestion pipeline</div>
              </div>
            </div>
            {(!data?.recent_alerts || data.recent_alerts.length === 0) ? (
              <div style={{ textAlign: "center", padding: "40px", color: "var(--sf-text-muted)" }}>
                <div style={{ display: "flex", justifyContent: "center", marginBottom: "12px" }}><ShieldCheck size={40} color="#10b981" opacity={0.5} /></div>
                <div style={{ fontSize: "14px", fontWeight: 600 }}>No alerts detected</div>
                <div style={{ fontSize: "12px", marginTop: "4px" }}>The ingestion pipeline will generate alerts automatically</div>
              </div>
            ) : (
              <table className="sf-table">
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Severity</th>
                    <th>Priority</th>
                    <th>MITRE</th>
                    <th>Status</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_alerts.map((alert: Alert) => (
                    <tr key={alert.id} onClick={() => window.location.href = `/alerts?id=${alert.id}`}>
                      <td style={{ color: "var(--sf-text-primary)", fontWeight: 500, maxWidth: "250px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {alert.title}
                      </td>
                      <td><span className={`sf-badge ${alert.severity}`}>{alert.severity}</span></td>
                      <td><span className={`sf-badge ${alert.priority?.toLowerCase()}`}>{alert.priority}</span></td>
                      <td style={{ fontFamily: "monospace", fontSize: "12px", color: "var(--sf-accent-light)" }}>{alert.mitre_id || "â€”"}</td>
                      <td><span className={`sf-badge ${alert.status}`}>{alert.status}</span></td>
                      <td style={{ fontSize: "12px", color: "var(--sf-text-muted)" }}>
                        {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : "â€”"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Agent Activity */}
          <div className="sf-card">
            <div className="sf-card-header">
              <div>
                <div className="sf-card-title">ðŸ¤– AI Agent Activity</div>
                <div className="sf-card-subtitle">Recent autonomous operations</div>
              </div>
            </div>
            {(!data?.recent_agent_activity || data.recent_agent_activity.length === 0) ? (
              <div style={{ textAlign: "center", padding: "30px", color: "var(--sf-text-muted)", fontSize: "13px" }}>
                No agent activity yet. Click &quot;AI Analyze&quot; on any alert to activate the AI agents.
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {data.recent_agent_activity.slice(0, 8).map((action: AgentActivity) => (
                  <div key={action.id} style={{
                    display: "flex", alignItems: "center", gap: "12px",
                    padding: "10px 14px", borderRadius: "8px",
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid var(--sf-border)",
                  }}>
                    <span style={{ fontSize: "16px" }}>
                      {action.agent_name === "triage_agent" ? "ðŸŽ¯" :
                       action.agent_name === "investigation_agent" ? "ðŸ”" :
                       action.agent_name === "remediation_agent" ? "ðŸ”§" :
                       action.agent_name === "it_support_agent" ? "ðŸ’»" :
                       action.agent_name === "reporting_agent" ? "ðŸ“Š" : "ðŸ¤–"}
                    </span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: "13px", fontWeight: 500, color: "var(--sf-text-primary)" }}>
                        {action.agent_name.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--sf-text-muted)" }}>
                        {action.output_summary || action.action_type}
                      </div>
                    </div>
                    <div style={{ textAlign: "right" }}>
                      <div style={{ fontSize: "12px", color: "var(--sf-accent-light)", fontWeight: 600 }}>
                        {(action.confidence * 100).toFixed(0)}%
                      </div>
                      <div style={{ fontSize: "10px", color: "var(--sf-text-muted)" }}>
                        {action.created_at ? new Date(action.created_at).toLocaleTimeString() : ""}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Risk Score */}
          <div className="sf-card" style={{ textAlign: "center" }}>
            <div className="sf-card-title" style={{ marginBottom: "16px" }}>Organization Risk Score</div>
            <div className="sf-risk-gauge">
              <svg viewBox="0 0 140 140">
                <circle className="sf-risk-gauge-bg" cx="70" cy="70" r="60" />
                <circle
                  className="sf-risk-gauge-fill"
                  cx="70" cy="70" r="60"
                  stroke={riskColor}
                  strokeDasharray={dashArray}
                />
              </svg>
              <div className="sf-risk-value">
                <div className="sf-risk-number" style={{ color: riskColor }}>{riskScore}</div>
                <div className="sf-risk-label" style={{ color: riskColor }}>{riskLevel}</div>
              </div>
            </div>
            <div style={{ fontSize: "12px", color: "var(--sf-text-muted)", marginTop: "12px" }}>
              Based on open alerts, incidents, and threat severity
            </div>
          </div>

          {/* Security Components Health */}
          <div className="sf-card">
            <div className="sf-card-title" style={{ marginBottom: "16px" }}>ðŸ”’ Security Architecture</div>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {[
                { name: "Prompt Injection Defense", status: health?.components?.security?.prompt_injection, icon: "ðŸ›¡ï¸", detail: "11 attack categories" },
                { name: "Output Validator", status: health?.components?.security?.output_validation, icon: "âœ…", detail: "PII, hallucination, canary" },
                { name: "Canary Token System", status: health?.components?.security?.canary_tokens, icon: "ðŸ¤", detail: "Prompt leakage detection" },
                { name: "Policy Engine", status: health?.components?.security?.policy_engine, icon: "ðŸ“‹", detail: "Action-level enforcement" },
                { name: "Knowledge Base (RAG)", status: health?.components?.knowledge_base?.status, icon: "ðŸ§ ", detail: `${health?.components?.knowledge_base?.documents ?? 0} documents` },
                { name: "Ingestion Pipeline", status: health?.components?.ingestion?.status, icon: "ðŸ“¡", detail: `${health?.components?.ingestion?.events_ingested ?? 0} events` },
              ].map((comp, i) => (
                <div key={i} style={{
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  padding: "8px 12px", borderRadius: "8px", background: "rgba(255,255,255,0.02)",
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span style={{ fontSize: "14px" }}>{comp.icon}</span>
                    <div>
                      <div style={{ fontSize: "12px", fontWeight: 500, color: "var(--sf-text-primary)" }}>{comp.name}</div>
                      <div style={{ fontSize: "10px", color: "var(--sf-text-muted)" }}>{comp.detail}</div>
                    </div>
                  </div>
                  <span style={{
                    fontSize: "10px", fontWeight: 600, padding: "2px 8px", borderRadius: "10px",
                    background: (comp.status === "active" || comp.status === "loaded" || comp.status === "running") ? "rgba(16,185,129,0.15)" : "rgba(239,68,68,0.15)",
                    color: (comp.status === "active" || comp.status === "loaded" || comp.status === "running") ? "#10b981" : "#ef4444",
                  }}>
                    {comp.status || "unknown"}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Severity Distribution */}
          <div className="sf-card">
            <div className="sf-card-title" style={{ marginBottom: "16px" }}>Alert Severity Distribution</div>
            {data?.severity_distribution && Object.keys(data.severity_distribution).length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {["critical", "high", "medium", "low"].map(sev => {
                  const count = data.severity_distribution[sev] || 0;
                  const total = Object.values(data.severity_distribution).reduce((a: number, b: any) => a + (b as number), 0) as number;
                  const pct = total > 0 ? (count / total) * 100 : 0;
                  const colors: Record<string, string> = { critical: "#dc2626", high: "#f97316", medium: "#eab308", low: "#22c55e" };
                  return (
                    <div key={sev}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "4px" }}>
                        <span style={{ textTransform: "capitalize", color: "var(--sf-text-secondary)" }}>{sev}</span>
                        <span style={{ fontWeight: 600, color: colors[sev] }}>{count}</span>
                      </div>
                      <div style={{ height: "6px", borderRadius: "3px", background: "rgba(255,255,255,0.05)" }}>
                        <div style={{
                          height: "100%", borderRadius: "3px", background: colors[sev],
                          width: `${pct}%`, transition: "width 1s ease",
                          boxShadow: `0 0 8px ${colors[sev]}40`,
                        }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ textAlign: "center", color: "var(--sf-text-muted)", fontSize: "13px", padding: "20px 0" }}>
                No alert data available
              </div>
            )}
          </div>

          {/* Attack Types */}
          {data?.top_attack_types && data.top_attack_types.length > 0 && (
            <div className="sf-card">
              <div className="sf-card-title" style={{ marginBottom: "16px" }}>Top Attack Types</div>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {data.top_attack_types.map((at, i) => (
                  <div key={i} style={{
                    display: "flex", justifyContent: "space-between", alignItems: "center",
                    padding: "8px 12px", borderRadius: "8px", background: "rgba(255,255,255,0.02)",
                  }}>
                    <span style={{ fontSize: "13px", textTransform: "capitalize" }}>
                      {at.type.replace(/_/g, " ")}
                    </span>
                    <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--sf-accent-light)" }}>
                      {at.count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

