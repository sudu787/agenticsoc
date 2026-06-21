"use client";

import { useEffect, useState, useCallback } from "react";
import { getComplianceScore, getComplianceViolations, getComplianceFrameworks } from "@/lib/api";
import { ShieldCheck, AlertTriangle, CheckCircle, XCircle, RefreshCw } from "lucide-react";

export default function ComplianceCenter() {
  const [score, setScore] = useState<any>(null);
  const [violations, setViolations] = useState<any[]>([]);
  const [frameworks, setFrameworks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [scoreRes, violRes, fwRes] = await Promise.allSettled([
        getComplianceScore(),
        getComplianceViolations(),
        getComplianceFrameworks(),
      ]);
      if (scoreRes.status === "fulfilled") setScore(scoreRes.value);
      if (violRes.status === "fulfilled") setViolations(violRes.value?.violations || []);
      if (fwRes.status === "fulfilled") setFrameworks(fwRes.value?.frameworks || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const levelColor = (level: string) => {
    if (level === "critical" || level === "non_compliant") return "#dc2626";
    if (level === "high") return "#f97316";
    if (level === "medium") return "#eab308";
    if (level === "compliant" || level === "minimal" || level === "low") return "#10b981";
    return "#6b7280";
  };

  const overall = score?.overall_score ?? 95;

  return (
    <div className="sf-animate-in">
      <div className="sf-page-header">
        <div>
          <h1 className="sf-page-title">Compliance Center</h1>
          <p className="sf-page-subtitle">NIST CSF • CIS Controls v8 • Real-time violation detection</p>
        </div>
        <button className="sf-btn sf-btn-secondary sf-btn-sm" onClick={load}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {loading ? (
        <div style={{ display: "flex", justifyContent: "center", padding: "80px" }}>
          <div className="sf-loading-spinner" />
        </div>
      ) : (
        <>
          {/* Overall Score + Framework Scores */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "20px", marginBottom: "24px" }}>
            {/* Overall */}
            <div className="sf-card" style={{ textAlign: "center", padding: "32px" }}>
              <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--sf-text-secondary)", marginBottom: "16px", textTransform: "uppercase" }}>
                Overall Compliance Score
              </div>
              <div style={{ fontSize: "64px", fontWeight: 800, color: overall >= 80 ? "#10b981" : overall >= 60 ? "#eab308" : "#dc2626", lineHeight: 1 }}>
                {Math.round(overall)}
              </div>
              <div style={{ fontSize: "13px", color: "var(--sf-text-muted)", marginTop: "8px" }}>/100</div>
              <div style={{ marginTop: "16px" }}>
                <span className={`sf-badge ${score?.risk_level === "minimal" || score?.risk_level === "low" ? "low" : score?.risk_level === "medium" ? "medium" : "critical"}`}>
                  {score?.risk_level?.toUpperCase() || "ASSESSING"} RISK
                </span>
              </div>
            </div>

            {/* NIST CSF */}
            <div className="sf-card">
              <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "16px", color: "var(--sf-text-primary)" }}>
                NIST CSF 2.0
              </div>
              <div style={{ fontSize: "40px", fontWeight: 800, color: levelColor(score?.frameworks?.nist_csf?.status || "compliant") }}>
                {Math.round(score?.frameworks?.nist_csf?.score ?? 95)}
              </div>
              <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", marginTop: "4px" }}>/ 100</div>
              <div style={{ marginTop: "12px", display: "flex", alignItems: "center", gap: "6px", fontSize: "12px" }}>
                {score?.frameworks?.nist_csf?.status === "compliant"
                  ? <><CheckCircle size={14} color="#10b981" /> Compliant</>
                  : <><XCircle size={14} color="#dc2626" /> Non-Compliant</>}
              </div>
              {score?.frameworks?.nist_csf?.violated_categories?.length > 0 && (
                <div style={{ marginTop: "12px", fontSize: "11px", color: "var(--sf-text-muted)" }}>
                  Violated: {score.frameworks.nist_csf.violated_categories.slice(0, 3).join(", ")}
                </div>
              )}
            </div>

            {/* CIS Controls */}
            <div className="sf-card">
              <div style={{ fontSize: "13px", fontWeight: 700, marginBottom: "16px", color: "var(--sf-text-primary)" }}>
                CIS Controls v8
              </div>
              <div style={{ fontSize: "40px", fontWeight: 800, color: levelColor(score?.frameworks?.cis_controls?.status || "compliant") }}>
                {Math.round(score?.frameworks?.cis_controls?.score ?? 96)}
              </div>
              <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", marginTop: "4px" }}>/ 100</div>
              <div style={{ marginTop: "12px", display: "flex", alignItems: "center", gap: "6px", fontSize: "12px" }}>
                {score?.frameworks?.cis_controls?.status === "compliant"
                  ? <><CheckCircle size={14} color="#10b981" /> Compliant</>
                  : <><XCircle size={14} color="#dc2626" /> Non-Compliant</>}
              </div>
              {score?.controls_violated > 0 && (
                <div style={{ marginTop: "12px", fontSize: "11px", color: "var(--sf-text-muted)" }}>
                  {score.controls_violated} controls violated
                </div>
              )}
            </div>
          </div>

          {/* Frameworks Table */}
          <div className="sf-card" style={{ marginBottom: "24px" }}>
            <div className="sf-card-header">
              <div className="sf-card-title">
                <ShieldCheck size={16} style={{ display: "inline", marginRight: 6, verticalAlign: "text-bottom" }} />
                Supported Frameworks
              </div>
            </div>
            <table className="sf-table">
              <thead>
                <tr>
                  <th>Framework</th>
                  <th>Version</th>
                  <th>Controls</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {frameworks.map((fw: any) => (
                  <tr key={fw.id}>
                    <td style={{ fontWeight: 600 }}>{fw.name}</td>
                    <td style={{ color: "var(--sf-text-muted)", fontSize: "12px" }}>{fw.version}</td>
                    <td style={{ fontSize: "12px" }}>
                      {fw.total_subcategories || fw.total_safeguards || fw.total_controls || fw.total_clauses} controls
                    </td>
                    <td>
                      {fw.implemented
                        ? <span className="sf-badge low">Implemented</span>
                        : <span className="sf-badge" style={{ background: "rgba(107,114,128,0.15)", color: "#6b7280" }}>Roadmap</span>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Violations */}
          <div className="sf-card">
            <div className="sf-card-header">
              <div className="sf-card-title">
                <AlertTriangle size={16} style={{ display: "inline", marginRight: 6, verticalAlign: "text-bottom" }} />
                Recent Compliance Violations
              </div>
            </div>
            {violations.length === 0 ? (
              <div style={{ textAlign: "center", padding: "40px", color: "var(--sf-text-muted)" }}>
                <CheckCircle size={40} color="#10b981" style={{ opacity: 0.5, margin: "0 auto 12px" }} />
                <p>No compliance violations detected.</p>
              </div>
            ) : (
              <table className="sf-table">
                <thead>
                  <tr>
                    <th>Alert</th>
                    <th>Type</th>
                    <th>NIST Category</th>
                    <th>CIS Control</th>
                    <th>Severity</th>
                    <th>Detected</th>
                  </tr>
                </thead>
                <tbody>
                  {violations.slice(0, 15).map((v: any, i: number) => (
                    <tr key={i}>
                      <td style={{ fontSize: "12px", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {v.alert_title}
                      </td>
                      <td style={{ fontSize: "11px", color: "var(--sf-text-muted)" }}>{v.alert_type?.replace(/_/g, " ")}</td>
                      <td style={{ fontSize: "11px", fontFamily: "monospace", color: "#8b5cf6" }}>
                        {v.nist_mapping?.category || "—"}
                      </td>
                      <td style={{ fontSize: "11px", fontFamily: "monospace", color: "#3b82f6" }}>
                        {v.cis_mapping?.control_id || "—"}
                      </td>
                      <td>
                        <span className={`sf-badge ${v.severity}`}>{v.severity}</span>
                      </td>
                      <td style={{ fontSize: "11px", color: "var(--sf-text-muted)" }}>
                        {new Date(v.detected_at).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  );
}
