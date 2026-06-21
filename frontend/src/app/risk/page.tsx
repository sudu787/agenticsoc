"use client";

import { useEffect, useState, useCallback } from "react";
import { getOrgRiskScore, getRiskTrend, getAssetRisks } from "@/lib/api";
import { Shield, TrendingUp, TrendingDown, AlertTriangle, Server, RefreshCw } from "lucide-react";

export default function RiskCenter() {
  const [orgRisk, setOrgRisk] = useState<any>(null);
  const [trend, setTrend] = useState<any>(null);
  const [assets, setAssets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [riskRes, trendRes, assetRes] = await Promise.allSettled([
        getOrgRiskScore(),
        getRiskTrend(),
        getAssetRisks(),
      ]);
      if (riskRes.status === "fulfilled") setOrgRisk(riskRes.value);
      if (trendRes.status === "fulfilled") setTrend(trendRes.value);
      if (assetRes.status === "fulfilled") setAssets(assetRes.value?.assets || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  const riskColor = (level: string) => {
    switch (level) {
      case "critical": return "#dc2626";
      case "high": return "#f97316";
      case "medium": return "#eab308";
      case "low": return "#10b981";
      default: return "#6b7280";
    }
  };

  const score = orgRisk?.org_risk_score ?? orgRisk?.risk_score ?? 0;
  const level = orgRisk?.risk_level ?? "minimal";
  const circumference = 2 * Math.PI * 70;
  const dashArray = `${(score / 100) * circumference} ${circumference}`;

  return (
    <div className="sf-animate-in">
      <div className="sf-page-header">
        <div>
          <h1 className="sf-page-title">Risk Center</h1>
          <p className="sf-page-subtitle">Real-time organizational security risk posture • Multi-dimensional scoring</p>
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
          {/* Main Risk Score + Breakdown */}
          <div style={{ display: "grid", gridTemplateColumns: "320px 1fr", gap: "24px", marginBottom: "24px" }}>
            {/* Circular Score */}
            <div className="sf-card" style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "32px" }}>
              <h3 style={{ fontSize: "14px", fontWeight: 600, color: "var(--sf-text-secondary)", marginBottom: "24px", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                Organizational Risk Score
              </h3>
              <div style={{ position: "relative", width: 160, height: 160 }}>
                <svg width="160" height="160" viewBox="0 0 160 160" style={{ transform: "rotate(-90deg)" }}>
                  <circle cx="80" cy="80" r="70" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="14" />
                  <circle
                    cx="80" cy="80" r="70" fill="none"
                    stroke={riskColor(level)} strokeWidth="14"
                    strokeDasharray={dashArray}
                    strokeLinecap="round"
                    style={{ transition: "stroke-dasharray 1s ease", filter: `drop-shadow(0 0 10px ${riskColor(level)})` }}
                  />
                </svg>
                <div style={{
                  position: "absolute", inset: 0, display: "flex", flexDirection: "column",
                  alignItems: "center", justifyContent: "center",
                }}>
                  <span style={{ fontSize: "40px", fontWeight: 800, color: riskColor(level), lineHeight: 1 }}>
                    {Math.round(score)}
                  </span>
                  <span style={{ fontSize: "12px", fontWeight: 700, color: riskColor(level), textTransform: "uppercase", letterSpacing: "0.1em" }}>
                    {level}
                  </span>
                </div>
              </div>

              <div style={{ marginTop: "24px", fontSize: "12px", color: "var(--sf-text-secondary)", textAlign: "center", lineHeight: 1.6 }}>
                {orgRisk?.recommendation || "System operating normally."}
              </div>
            </div>

            {/* Score Breakdown */}
            <div className="sf-card">
              <div className="sf-card-header">
                <div className="sf-card-title">
                  <TrendingUp size={16} style={{ display: "inline", marginRight: 6, verticalAlign: "text-bottom" }} />
                  Risk Score Breakdown
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "16px", marginBottom: "24px" }}>
                {Object.entries(orgRisk?.breakdown || {}).map(([key, val]: any) => (
                  <div key={key} style={{ background: "rgba(255,255,255,0.03)", borderRadius: "8px", padding: "16px", textAlign: "center" }}>
                    <div style={{ fontSize: "28px", fontWeight: 700, color: val > 20 ? "#dc2626" : val > 10 ? "#f97316" : "#10b981" }}>
                      {Math.round(val)}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", marginTop: "4px", textTransform: "capitalize" }}>
                      {key.replace(/_/g, " ")}
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                <div style={{ background: "rgba(220,38,38,0.08)", border: "1px solid rgba(220,38,38,0.2)", borderRadius: "8px", padding: "16px" }}>
                  <div style={{ fontSize: "24px", fontWeight: 700, color: "#dc2626" }}>{orgRisk?.open_critical_alerts ?? 0}</div>
                  <div style={{ fontSize: "12px", color: "var(--sf-text-muted)", marginTop: "4px" }}>Critical Open Alerts</div>
                </div>
                <div style={{ background: "rgba(249,115,22,0.08)", border: "1px solid rgba(249,115,22,0.2)", borderRadius: "8px", padding: "16px" }}>
                  <div style={{ fontSize: "24px", fontWeight: 700, color: "#f97316" }}>{orgRisk?.open_incidents ?? 0}</div>
                  <div style={{ fontSize: "12px", color: "var(--sf-text-muted)", marginTop: "4px" }}>Active Incidents</div>
                </div>
              </div>
            </div>
          </div>

          {/* Asset Risk Table */}
          <div className="sf-card">
            <div className="sf-card-header">
              <div className="sf-card-title">
                <Server size={16} style={{ display: "inline", marginRight: 6, verticalAlign: "text-bottom" }} />
                Asset Risk Breakdown
              </div>
            </div>

            {assets.length === 0 ? (
              <div style={{ textAlign: "center", padding: "40px", color: "var(--sf-text-muted)" }}>
                <Shield size={40} style={{ opacity: 0.3, margin: "0 auto 12px" }} />
                <p>No assets at risk. System is healthy.</p>
              </div>
            ) : (
              <table className="sf-table">
                <thead>
                  <tr>
                    <th>Asset</th>
                    <th>Risk Score</th>
                    <th>Risk Level</th>
                    <th>Total Alerts</th>
                    <th>Critical</th>
                    <th>High</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset: any, i: number) => (
                    <tr key={i}>
                      <td style={{ fontFamily: "monospace", fontSize: "12px" }}>{asset.asset}</td>
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <div style={{
                            width: `${Math.min(asset.risk_score, 100)}px`, height: "6px",
                            background: riskColor(asset.risk_level), borderRadius: "3px",
                            maxWidth: "100px", transition: "width 0.5s ease",
                          }} />
                          <span style={{ color: riskColor(asset.risk_level), fontWeight: 600 }}>
                            {Math.round(asset.risk_score)}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className={`sf-badge ${asset.risk_level === "critical" ? "critical" : asset.risk_level === "high" ? "high" : "medium"}`}>
                          {asset.risk_level}
                        </span>
                      </td>
                      <td>{asset.total_alerts}</td>
                      <td style={{ color: "#dc2626", fontWeight: 600 }}>{asset.critical_alerts}</td>
                      <td style={{ color: "#f97316", fontWeight: 600 }}>{asset.high_alerts}</td>
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
