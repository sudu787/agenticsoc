"use client";

import { useEffect, useState, useCallback } from "react";
import { getApprovalQueue, getActionHistory, getAutonomousModes, approveAction, rejectAction } from "@/lib/api";
import { Zap, Clock, CheckCircle, XCircle, Shield, RefreshCw, Play } from "lucide-react";

const MODE_COLORS: Record<string, string> = {
  human_approval: "#6b7280",
  risk_aware: "#3b82f6",
  autonomous: "#8b5cf6",
  emergency: "#dc2626",
};

export default function AutonomousResponsePage() {
  const [queue, setQueue] = useState<any[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [modes, setModes] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeMode, setActiveMode] = useState("risk_aware");
  const [approvingIdx, setApprovingIdx] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const [queueRes, histRes, modesRes] = await Promise.allSettled([
        getApprovalQueue(),
        getActionHistory(),
        getAutonomousModes(),
      ]);
      if (queueRes.status === "fulfilled") setQueue(queueRes.value?.actions || []);
      if (histRes.status === "fulfilled") setHistory(histRes.value?.actions || []);
      if (modesRes.status === "fulfilled") setModes(modesRes.value?.modes || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [load]);

  const handleApprove = async (idx: number) => {
    setApprovingIdx(idx);
    try {
      await approveAction(idx, "analyst@secureflow.ai");
      await load();
    } catch (e) {
      console.error(e);
    } finally {
      setApprovingIdx(null);
    }
  };

  const handleReject = async (idx: number) => {
    try {
      await rejectAction(idx, "analyst@secureflow.ai", "Manual review required");
      await load();
    } catch (e) {
      console.error(e);
    }
  };

  const statusColor = (status: string) => {
    if (status === "auto_executed" || status === "approved_executed") return "#10b981";
    if (status === "pending_approval") return "#f59e0b";
    if (status === "rejected") return "#dc2626";
    return "#6b7280";
  };

  return (
    <div className="sf-animate-in">
      <div className="sf-page-header">
        <div>
          <h1 className="sf-page-title">Autonomous Response</h1>
          <p className="sf-page-subtitle">AI-driven security containment • Human-in-the-loop approval queue</p>
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
          {/* Autonomy Mode Selector */}
          <div className="sf-card" style={{ marginBottom: "24px" }}>
            <div className="sf-card-header">
              <div className="sf-card-title">
                <Zap size={16} style={{ display: "inline", marginRight: 6, verticalAlign: "text-bottom" }} />
                Autonomy Mode
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px" }}>
              {modes.map((mode: any) => (
                <button
                  key={mode.id}
                  onClick={() => setActiveMode(mode.id)}
                  style={{
                    padding: "16px",
                    borderRadius: "8px",
                    border: `2px solid ${activeMode === mode.id ? MODE_COLORS[mode.id] : "var(--sf-border)"}`,
                    background: activeMode === mode.id ? `${MODE_COLORS[mode.id]}15` : "rgba(255,255,255,0.02)",
                    cursor: "pointer",
                    textAlign: "left",
                    transition: "all 0.2s ease",
                  }}
                >
                  <div style={{ fontSize: "13px", fontWeight: 700, color: activeMode === mode.id ? MODE_COLORS[mode.id] : "var(--sf-text-primary)", marginBottom: "4px" }}>
                    {mode.name}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", lineHeight: 1.4 }}>
                    {mode.description}
                  </div>
                  <div style={{ marginTop: "8px", fontSize: "10px", color: "var(--sf-text-muted)", fontStyle: "italic" }}>
                    {mode.recommended_for}
                  </div>
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
            {/* Approval Queue */}
            <div className="sf-card">
              <div className="sf-card-header">
                <div className="sf-card-title">
                  <Clock size={16} style={{ display: "inline", marginRight: 6, verticalAlign: "text-bottom" }} />
                  Pending Approval Queue
                </div>
                <span className="sf-badge" style={{ background: queue.length > 0 ? "rgba(245,158,11,0.15)" : "rgba(16,185,129,0.1)", color: queue.length > 0 ? "#f59e0b" : "#10b981" }}>
                  {queue.length} pending
                </span>
              </div>

              {queue.length === 0 ? (
                <div style={{ textAlign: "center", padding: "40px", color: "var(--sf-text-muted)" }}>
                  <CheckCircle size={36} color="#10b981" style={{ opacity: 0.4, margin: "0 auto 12px" }} />
                  <p style={{ fontSize: "13px" }}>No actions pending approval</p>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                  {queue.map((action: any, idx: number) => (
                    <div key={idx} style={{
                      background: "rgba(245,158,11,0.05)",
                      border: "1px solid rgba(245,158,11,0.2)",
                      borderRadius: "8px",
                      padding: "16px",
                    }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                        <div>
                          <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--sf-text-primary)" }}>{action.action}</div>
                          <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", fontFamily: "monospace" }}>→ {action.target}</div>
                        </div>
                        <span className={`sf-badge ${action.risk_level}`}>{action.risk_level}</span>
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--sf-text-secondary)", marginBottom: "12px" }}>
                        {action.justification}
                      </div>
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button
                          className="sf-btn sf-btn-sm"
                          style={{ background: "rgba(16,185,129,0.15)", color: "#10b981", border: "1px solid rgba(16,185,129,0.3)", flex: 1 }}
                          onClick={() => handleApprove(idx)}
                          disabled={approvingIdx === idx}
                        >
                          <CheckCircle size={12} /> Approve
                        </button>
                        <button
                          className="sf-btn sf-btn-sm sf-btn-outline"
                          style={{ color: "#dc2626", border: "1px solid rgba(220,38,38,0.3)", flex: 1 }}
                          onClick={() => handleReject(idx)}
                        >
                          <XCircle size={12} /> Reject
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Action History */}
            <div className="sf-card">
              <div className="sf-card-header">
                <div className="sf-card-title">
                  <Shield size={16} style={{ display: "inline", marginRight: 6, verticalAlign: "text-bottom" }} />
                  Execution History
                </div>
              </div>

              {history.length === 0 ? (
                <div style={{ textAlign: "center", padding: "40px", color: "var(--sf-text-muted)" }}>
                  <Play size={36} style={{ opacity: 0.3, margin: "0 auto 12px" }} />
                  <p style={{ fontSize: "13px" }}>No actions executed yet</p>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "400px", overflowY: "auto" }}>
                  {history.slice(-20).reverse().map((action: any, idx: number) => (
                    <div key={idx} style={{
                      display: "flex", alignItems: "center", gap: "12px",
                      padding: "12px", borderRadius: "6px",
                      background: "rgba(255,255,255,0.02)",
                      borderLeft: `3px solid ${statusColor(action.status)}`,
                    }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--sf-text-primary)" }}>{action.action}</div>
                        <div style={{ fontSize: "11px", color: "var(--sf-text-muted)", fontFamily: "monospace" }}>{action.target}</div>
                      </div>
                      <div style={{ textAlign: "right", flexShrink: 0 }}>
                        <div style={{ fontSize: "11px", color: statusColor(action.status), fontWeight: 600 }}>
                          {action.status?.replace(/_/g, " ")}
                        </div>
                        <div style={{ fontSize: "10px", color: "var(--sf-text-muted)" }}>
                          {action.executed_at ? new Date(action.executed_at).toLocaleTimeString() : ""}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
