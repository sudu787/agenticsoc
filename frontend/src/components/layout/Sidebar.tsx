"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { LayoutDashboard, BellRing, Target, Ticket, Brain, Network, MessageSquare, FileText, Bot, Gamepad2, Shield, ShieldCheck, Zap, TrendingUp } from "lucide-react";

const navItems = [
  { section: "Operations" },
  { href: "/", label: "Dashboard", Icon: LayoutDashboard },
  { href: "/alerts", label: "Alerts", Icon: BellRing },
  { href: "/incidents", label: "Incidents", Icon: Target },
  { href: "/tickets", label: "Tickets", Icon: Ticket },
  { section: "Intelligence" },
  { href: "/knowledge", label: "Knowledge Base", Icon: Brain },
  { href: "/graph", label: "Graph Explorer", Icon: Network },
  { href: "/chat", label: "AI Assistant", Icon: MessageSquare },
  { href: "/logs", label: "Log Viewer", Icon: FileText },
  { section: "Security" },
  { href: "/risk", label: "Risk Center", Icon: TrendingUp },
  { href: "/compliance", label: "Compliance", Icon: ShieldCheck },
  { href: "/autonomous", label: "Auto Response", Icon: Zap },
  { section: "System" },
  { href: "/agents", label: "Agent Status", Icon: Bot },
  { href: "/demo", label: "Demo Center", Icon: Gamepad2 },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="sf-sidebar">
      {/* Logo */}
      <div className="sf-sidebar-logo">
        <div className="sf-sidebar-logo-icon">🛡️</div>
        <div>
          <div className="sf-sidebar-logo-text">SecureFlow AI</div>
          <div className="sf-sidebar-logo-badge">v1.0</div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1 }}>
        {navItems.map((item, i) => {
          if ("section" in item && !("href" in item)) {
            return (
              <div key={i} className="sf-sidebar-section">
                {item.section}
              </div>
            );
          }
          if ("href" in item) {
            const isActive = pathname === item.href;
            const IconComp = (item as any).Icon;
            return (
              <Link
                key={item.href}
                href={item.href!}
                className={`sf-sidebar-link ${isActive ? "active" : ""}`}
                style={{ position: "relative" }}
              >
                <span className="sf-sidebar-icon">
                  {IconComp && <IconComp size={16} />}
                </span>
                <span>{item.label}</span>
              </Link>
            );
          }
          return null;
        })}
      </nav>

      {/* Footer */}
      <div style={{
        padding: "16px 12px",
        borderTop: "1px solid var(--sf-border)",
        marginTop: "auto",
      }}>
        <div style={{ fontSize: "11px", color: "var(--sf-text-muted)" }}>
          SecureFlow AI Platform
        </div>
        <div style={{ fontSize: "10px", color: "var(--sf-text-muted)", marginTop: "4px" }}>
          © 2026 • All systems operational
        </div>
      </div>
    </aside>
  );
}
