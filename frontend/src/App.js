import { useState, useEffect, useRef } from "react";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

const SEVERITY_COLORS = {
  Critical: "#ff003c",
  High: "#ff6b00",
  Medium: "#f5c400",
  Low: "#00ff9d",
};

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];

// Animated glitch text effect
function GlitchText({ text }) {
  return (
    <span style={styles.glitch} data-text={text}>
      {text}
    </span>
  );
}

// Animated counter
function Counter({ value }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    let start = 0;
    const end = parseInt(value);
    if (start === end) return;
    const timer = setInterval(() => {
      start += 1;
      setCount(start);
      if (start === end) clearInterval(timer);
    }, 30);
    return () => clearInterval(timer);
  }, [value]);
  return <span>{count}</span>;
}

export default function App() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(0);
  const [scanPhase, setScanPhase] = useState("");
  const [particles, setParticles] = useState([]);
  const canvasRef = useRef(null);

  // Animated background particles
  useEffect(() => {
    const pts = Array.from({ length: 60 }, (_, i) => ({
      id: i,
      x: Math.random() * 100,
      y: Math.random() * 100,
      size: Math.random() * 2 + 0.5,
      speed: Math.random() * 0.3 + 0.1,
      opacity: Math.random() * 0.5 + 0.1,
    }));
    setParticles(pts);
  }, []);

  const phases = [
    "INITIALIZING CRAWLER...",
    "AI ANALYZING ATTACK SURFACE...",
    "INJECTING PAYLOADS...",
    "SCANNING PORTS...",
    "CHECKING SSL CERTIFICATES...",
    "ENUMERATING SUBDOMAINS...",
    "RUNNING AI ANALYSIS...",
    "GENERATING REPORT...",
  ];

  const startScan = async () => {
    if (!url.trim()) return;
    setScanning(true);
    setError("");
    setScanData(null);
    setProgress(0);
    setScanPhase(phases[0]);

    try {
      const res = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const { scan_id } = await res.json();

      let attempts = 0;
      const poll = setInterval(async () => {
        attempts++;
        const p = Math.min(92, attempts * 3);
        setProgress(p);
        setScanPhase(phases[Math.floor((p / 100) * phases.length)] || phases[phases.length - 1]);

        const r = await fetch(`http://localhost:8000/results/${scan_id}`);
        const data = await r.json();
        if (data.status === "complete") {
          clearInterval(poll);
          setProgress(100);
          setScanPhase("SCAN COMPLETE");
          setScanData(data);
          setScanning(false);
        }
        if (attempts > 90) {
          clearInterval(poll);
          setError("Scan timed out. Try again.");
          setScanning(false);
        }
      }, 2000);
    } catch (e) {
      setError("Cannot connect to backend on port 8000.");
      setScanning(false);
    }
  };

  const pieData = scanData
    ? SEVERITY_ORDER.filter((s) => scanData.summary[s] > 0).map((s) => ({
        name: s,
        value: scanData.summary[s],
      }))
    : [];

  return (
    <div style={styles.root}>
      {/* Animated grid background */}
      <div style={styles.grid} />

      {/* Floating particles */}
      <div style={styles.particleContainer}>
        {particles.map((p) => (
          <div
            key={p.id}
            style={{
              position: "absolute",
              left: `${p.x}%`,
              top: `${p.y}%`,
              width: p.size,
              height: p.size,
              borderRadius: "50%",
              background: "#00ff9d",
              opacity: p.opacity,
              boxShadow: `0 0 ${p.size * 3}px #00ff9d`,
              animation: `float ${3 / p.speed}s ease-in-out infinite alternate`,
            }}
          />
        ))}
      </div>

      {/* Header */}
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <div style={styles.logoMark}>
            <svg width="36" height="36" viewBox="0 0 36 36">
              <polygon points="18,2 34,10 34,26 18,34 2,26 2,10" fill="none" stroke="#00ff9d" strokeWidth="1.5" />
              <polygon points="18,8 28,13 28,23 18,28 8,23 8,13" fill="none" stroke="#00ff9d" strokeWidth="1" opacity="0.5" />
              <circle cx="18" cy="18" r="4" fill="#00ff9d" />
            </svg>
          </div>
          <div>
            <div style={styles.logoText}>VULNSHIELD<span style={styles.logoAi}>.AI</span></div>
            <div style={styles.logoSub}>AUTONOMOUS THREAT DETECTION v4.0</div>
          </div>
        </div>
        <div style={styles.headerRight}>
          <div style={styles.statusPill}>
            <span style={{
              ...styles.statusDot,
              background: scanning ? "#f5c400" : "#00ff9d",
              boxShadow: `0 0 8px ${scanning ? "#f5c400" : "#00ff9d"}`,
              animation: scanning ? "pulse 1s infinite" : "none",
            }} />
            <span style={{ color: scanning ? "#f5c400" : "#00ff9d", fontSize: 11, letterSpacing: 2 }}>
              {scanning ? "SCANNING" : "SYSTEM READY"}
            </span>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section style={styles.hero}>
        <div style={styles.heroTag}>// AI-POWERED VULNERABILITY SCANNER</div>
        <h1 style={styles.heroTitle}>
          DETECT.<br />
          ANALYZE.<br />
          <span style={styles.heroAccent}>NEUTRALIZE.</span>
        </h1>
        <p style={styles.heroDesc}>
          Powered by Groq LLaMA3 — scans for SQLi, XSS, open ports,<br />
          SSL issues, subdomain exposure & missing security headers.
        </p>

        {/* Scan Input */}
        <div style={styles.scanBox}>
          <div style={styles.scanInput}>
            <span style={styles.scanPrefix}>TARGET://</span>
            <input
              style={styles.input}
              type="text"
              placeholder="https://target-domain.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !scanning && startScan()}
              disabled={scanning}
            />
          </div>
          <button
            className="scan-btn"
            style={{
              ...styles.scanBtn,
              opacity: scanning ? 0.7 : 1,
              cursor: scanning ? "not-allowed" : "pointer",
            }}
            onClick={startScan}
            disabled={scanning}
          >
            {scanning ? (
              <span style={styles.btnContent}>
                <span style={styles.spinner} />
                SCANNING...
              </span>
            ) : (
              <span style={styles.btnContent}>
                INITIATE SCAN
              </span>
            )}
          </button>
        </div>

        {/* Progress */}
        {scanning && (
          <div style={styles.progressWrap}>
            <div style={styles.progressHeader}>
              <span style={styles.progressPhase}>{scanPhase}</span>
              <span style={styles.progressPct}>{progress}%</span>
            </div>
            <div style={styles.progressTrack}>
              <div style={{ ...styles.progressFill, width: `${progress}%` }} />
              <div style={{ ...styles.progressGlow, width: `${progress}%` }} />
            </div>
          </div>
        )}

        {error && (
          <div style={styles.errorBox}>
            <span style={{ color: "#ff003c" }}>⚠</span> {error}
          </div>
        )}
      </section>

      {/* Results */}
      {scanData && (
        <section style={styles.results}>
          {/* Summary Cards */}
          <div style={styles.summaryRow}>
            {SEVERITY_ORDER.map((s) => (
              <div key={s} style={{ ...styles.summaryCard, borderColor: SEVERITY_COLORS[s] }}>
                <div style={{ ...styles.summaryGlow, background: SEVERITY_COLORS[s] }} />
                <div style={{ ...styles.summaryNum, color: SEVERITY_COLORS[s] }}>
                  <Counter value={scanData.summary[s] || 0} />
                </div>
                <div style={styles.summaryLabel}>{s.toUpperCase()}</div>
                <div style={{ ...styles.summaryBar, background: SEVERITY_COLORS[s], width: `${Math.min(100, (scanData.summary[s] || 0) * 20)}%` }} />
              </div>
            ))}
            <div style={{ ...styles.summaryCard, borderColor: "#00cfff" }}>
              <div style={{ ...styles.summaryGlow, background: "#00cfff" }} />
              <div style={{ ...styles.summaryNum, color: "#00cfff" }}>
                <Counter value={scanData.total} />
              </div>
              <div style={styles.summaryLabel}>TOTAL FINDINGS</div>
              <div style={{ ...styles.summaryBar, background: "#00cfff", width: "100%" }} />
            </div>
          </div>

          {/* Main Grid */}
          <div style={styles.mainGrid}>
            {/* Findings Table */}
            <div style={styles.card}>
              <div style={styles.cardHeader}>
                <span style={styles.cardIcon}>◈</span>
                <span style={styles.cardTitle}>VULNERABILITY FINDINGS</span>
                <span style={styles.cardCount}>{scanData.findings.length} DETECTED</span>
              </div>
              <div style={styles.tableWrap}>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      {["TYPE", "SEVERITY", "PARAMETER", "DESCRIPTION"].map((h) => (
                        <th key={h} style={styles.th}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {scanData.findings.map((f, i) => (
                      <tr key={i} style={{
                        ...styles.tr,
                        borderLeft: `3px solid ${SEVERITY_COLORS[f.severity]}22`,
                      }}>
                        <td style={styles.td}>
                          <span style={styles.typeChip}>{f.type}</span>
                        </td>
                        <td style={styles.td}>
                          <span style={{
                            ...styles.badge,
                            background: SEVERITY_COLORS[f.severity] + "18",
                            color: SEVERITY_COLORS[f.severity],
                            borderColor: SEVERITY_COLORS[f.severity] + "66",
                            boxShadow: `0 0 8px ${SEVERITY_COLORS[f.severity]}33`,
                          }}>
                            {f.severity}
                          </span>
                        </td>
                        <td style={{ ...styles.td, fontFamily: "monospace", fontSize: 11, color: "#00cfff" }}>
                          {f.parameter}
                        </td>
                        <td style={{ ...styles.td, fontSize: 12, color: "#7a9ab5" }}>
                          {f.description}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Chart */}
            {pieData.length > 0 && (
              <div style={styles.card}>
                <div style={styles.cardHeader}>
                  <span style={styles.cardIcon}>◈</span>
                  <span style={styles.cardTitle}>RISK DISTRIBUTION</span>
                </div>
                <ResponsiveContainer width="100%" height={260}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={65}
                      outerRadius={100}
                      paddingAngle={4}
                      dataKey="value"
                      strokeWidth={0}
                    >
                      {pieData.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={SEVERITY_COLORS[entry.name]}
                          style={{ filter: `drop-shadow(0 0 6px ${SEVERITY_COLORS[entry.name]})` }}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "#060e1a",
                        border: "1px solid #00ff9d33",
                        borderRadius: 6,
                        color: "#e0f0ff",
                        fontSize: 12,
                      }}
                    />
                    <Legend
                      formatter={(value) => (
                        <span style={{ color: SEVERITY_COLORS[value], fontSize: 11, letterSpacing: 1 }}>
                          {value}
                        </span>
                      )}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div style={styles.scannedUrl}>
                  <span style={{ color: "#7a9ab5" }}>TARGET: </span>
                  <span style={{ color: "#00cfff" }}>{scanData.url}</span>
                </div>
              </div>
            )}
          </div>

          {/* AI Analysis */}
          {scanData.ai_analysis?.summary && (
            <div style={styles.aiCard}>
              <div style={styles.aiHeader}>
                <div style={styles.aiIconWrap}>
                  <span style={styles.aiIcon}>◆</span>
                </div>
                <div>
                  <div style={styles.aiTitle}>GROQ AI SECURITY ANALYSIS</div>
                  <div style={styles.aiModel}>Model: {scanData.ai_analysis.model} • {scanData.ai_analysis.findings_analyzed} findings analyzed</div>
                </div>
              </div>
              <div style={styles.aiDivider} />
              <div style={styles.aiText}>{scanData.ai_analysis.summary}</div>
            </div>
          )}
        </section>
      )}

      {/* Footer */}
      <footer style={styles.footer}>
        <span style={{ color: "#00ff9d44" }}>⬡</span>
        {" "}VULNSHIELD AI • ETHICAL USE ONLY • ONLY SCAN SITES YOU OWN OR HAVE PERMISSION TO TEST{" "}
        <span style={{ color: "#00ff9d44" }}>⬡</span>
      </footer>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #040d18; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes float { 0%{transform:translateY(0)} 100%{transform:translateY(-15px)} }
        @keyframes spin { to{transform:rotate(360deg)} }
        @keyframes scanline {
          0%{transform:translateY(-100%)}
          100%{transform:translateY(100vh)}
        }
        .scan-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 0 30px #00ff9d66, 0 4px 15px rgba(0,0,0,0.3);
        }
        .scan-btn:active {
          transform: translateY(0);
        }
      `}</style>
    </div>
  );
}

const styles = {
  root: {
    minHeight: "100vh",
    background: "#040d18",
    color: "#e0f0ff",
    fontFamily: "'Share Tech Mono', monospace",
    position: "relative",
    overflowX: "hidden",
  },
  grid: {
    position: "fixed", inset: 0, zIndex: 0,
    backgroundImage: `
      linear-gradient(rgba(0,255,157,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,255,157,0.03) 1px, transparent 1px)
    `,
    backgroundSize: "40px 40px",
    pointerEvents: "none",
  },
  particleContainer: {
    position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none",
  },
  header: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    padding: "20px 48px",
    borderBottom: "1px solid #00ff9d18",
    backdropFilter: "blur(10px)",
    background: "rgba(4,13,24,0.8)",
    position: "sticky", top: 0, zIndex: 100,
  },
  headerLeft: { display: "flex", alignItems: "center", gap: 16 },
  logoMark: { flexShrink: 0 },
  logoText: {
    fontSize: 22, fontFamily: "'Orbitron', sans-serif",
    fontWeight: 900, letterSpacing: 4, color: "#e0f0ff",
  },
  logoAi: { color: "#00ff9d" },
  logoSub: { fontSize: 9, letterSpacing: 3, color: "#00ff9d66", marginTop: 2 },
  headerRight: {},
  statusPill: {
    display: "flex", alignItems: "center", gap: 8,
    background: "#0a1a2e", border: "1px solid #00ff9d22",
    padding: "6px 14px", borderRadius: 20,
  },
  statusDot: {
    width: 8, height: 8, borderRadius: "50%", display: "inline-block",
  },
  hero: {
    padding: "80px 48px 60px",
    maxWidth: 1000, margin: "0 auto",
    position: "relative", zIndex: 1,
  },
  heroTag: {
    color: "#00ff9d88", fontSize: 11, letterSpacing: 4, marginBottom: 20,
  },
  heroTitle: {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: "clamp(42px, 7vw, 80px)",
    fontWeight: 900, lineHeight: 1.05,
    letterSpacing: 2, marginBottom: 24,
    color: "#e0f0ff",
  },
  heroAccent: {
    color: "#00ff9d",
    textShadow: "0 0 40px #00ff9d66",
  },
  glitch: {},
  heroDesc: {
    color: "#7a9ab5", fontSize: 14, lineHeight: 1.8,
    marginBottom: 40, letterSpacing: 0.5,
  },
  scanBox: {
    display: "flex", gap: 12, flexWrap: "wrap",
    background: "#0a1a2e",
    border: "1px solid #00ff9d33",
    borderRadius: 8, padding: 6,
    boxShadow: "0 0 40px #00ff9d11",
  },
  scanInput: {
    flex: 1, minWidth: 260,
    display: "flex", alignItems: "center",
    padding: "4px 12px", gap: 8,
  },
  scanPrefix: {
    color: "#00ff9d66", fontSize: 12,
    whiteSpace: "nowrap", letterSpacing: 1,
  },
  input: {
    flex: 1, background: "transparent",
    border: "none", outline: "none",
    color: "#e0f0ff", fontSize: 14,
    fontFamily: "'Share Tech Mono', monospace",
    padding: "10px 0",
  },
  scanBtn: {
    background: "linear-gradient(135deg, #00ff9d, #00cfff)",
    color: "#040d18", border: "none",
    borderRadius: 6, padding: "12px 28px",
    fontSize: 13, fontWeight: 900,
    letterSpacing: 2, whiteSpace: "nowrap",
    fontFamily: "'Orbitron', sans-serif",
    transition: "all 0.2s",
    boxShadow: "0 0 20px #00ff9d44",
  },
  btnContent: { display: "flex", alignItems: "center", gap: 8 },
  spinner: {
    width: 14, height: 14,
    border: "2px solid #040d1844",
    borderTop: "2px solid #040d18",
    borderRadius: "50%",
    animation: "spin 0.7s linear infinite",
    display: "inline-block",
  },
  progressWrap: { marginTop: 20 },
  progressHeader: {
    display: "flex", justifyContent: "space-between",
    marginBottom: 8,
  },
  progressPhase: { color: "#00ff9d", fontSize: 11, letterSpacing: 2 },
  progressPct: { color: "#7a9ab5", fontSize: 11 },
  progressTrack: {
    height: 4, background: "#0a1a2e",
    borderRadius: 2, overflow: "hidden",
    position: "relative",
  },
  progressFill: {
    height: "100%",
    background: "linear-gradient(90deg, #00ff9d, #00cfff)",
    transition: "width 0.5s ease",
    borderRadius: 2,
  },
  progressGlow: {
    position: "absolute", top: 0, left: 0,
    height: "100%",
    background: "linear-gradient(90deg, #00ff9d66, #00cfff66)",
    filter: "blur(4px)",
    transition: "width 0.5s ease",
  },
  errorBox: {
    marginTop: 16, color: "#ff003c",
    fontSize: 12, letterSpacing: 1,
    background: "#ff003c11",
    border: "1px solid #ff003c33",
    padding: "10px 16px", borderRadius: 6,
  },
  results: {
    padding: "0 48px 60px",
    maxWidth: 1300, margin: "0 auto",
    position: "relative", zIndex: 1,
  },
  summaryRow: {
    display: "flex", gap: 12,
    flexWrap: "wrap", marginBottom: 24,
  },
  summaryCard: {
    flex: "1 1 120px",
    background: "#060e1a",
    border: "1px solid",
    borderRadius: 8, padding: "20px 16px",
    textAlign: "center", position: "relative",
    overflow: "hidden",
  },
  summaryGlow: {
    position: "absolute", top: 0, left: "50%",
    transform: "translateX(-50%)",
    width: "60%", height: 1,
    filter: "blur(6px)",
    opacity: 0.8,
  },
  summaryNum: {
    fontSize: 42, fontFamily: "'Orbitron', sans-serif",
    fontWeight: 900, lineHeight: 1,
  },
  summaryLabel: {
    fontSize: 9, letterSpacing: 2,
    color: "#7a9ab5", marginTop: 6,
  },
  summaryBar: {
    position: "absolute", bottom: 0, left: 0,
    height: 2, transition: "width 1s ease",
    opacity: 0.6,
  },
  mainGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 320px",
    gap: 20, marginBottom: 20,
  },
  card: {
    background: "#060e1a",
    border: "1px solid #00ff9d18",
    borderRadius: 10, padding: 24,
    boxShadow: "0 4px 40px #00000044",
  },
  cardHeader: {
    display: "flex", alignItems: "center",
    gap: 10, marginBottom: 20,
  },
  cardIcon: { color: "#00ff9d", fontSize: 14 },
  cardTitle: {
    fontSize: 11, letterSpacing: 3,
    color: "#7a9ab5", flex: 1,
  },
  cardCount: {
    fontSize: 10, letterSpacing: 2,
    color: "#00ff9d88",
    background: "#00ff9d11",
    padding: "3px 10px", borderRadius: 20,
  },
  tableWrap: { overflowX: "auto" },
  table: { width: "100%", borderCollapse: "collapse" },
  th: {
    textAlign: "left", padding: "8px 12px",
    fontSize: 9, letterSpacing: 2, color: "#00ff9d66",
    borderBottom: "1px solid #00ff9d18",
  },
  tr: {
    borderBottom: "1px solid #ffffff06",
    transition: "background 0.2s",
  },
  td: { padding: "10px 12px", verticalAlign: "top", fontSize: 12 },
  typeChip: {
    fontSize: 11, color: "#c0d8f0",
  },
  badge: {
    display: "inline-block",
    padding: "3px 10px", borderRadius: 4,
    fontSize: 10, letterSpacing: 1,
    border: "1px solid", fontWeight: 700,
    fontFamily: "'Orbitron', sans-serif",
  },
  scannedUrl: {
    marginTop: 16, fontSize: 11,
    letterSpacing: 1, wordBreak: "break-all",
  },
  aiCard: {
    background: "#060e1a",
    border: "1px solid #00cfff33",
    borderRadius: 10, padding: 28,
    boxShadow: "0 0 40px #00cfff11",
  },
  aiHeader: {
    display: "flex", alignItems: "flex-start", gap: 16,
    marginBottom: 16,
  },
  aiIconWrap: {
    width: 44, height: 44, borderRadius: 8,
    background: "linear-gradient(135deg, #00ff9d22, #00cfff22)",
    border: "1px solid #00cfff44",
    display: "flex", alignItems: "center", justifyContent: "center",
    flexShrink: 0,
  },
  aiIcon: { color: "#00cfff", fontSize: 20 },
  aiTitle: {
    fontFamily: "'Orbitron', sans-serif",
    fontSize: 13, letterSpacing: 2, color: "#e0f0ff",
  },
  aiModel: { fontSize: 10, color: "#00cfff88", marginTop: 4, letterSpacing: 1 },
  aiDivider: {
    height: 1, background: "linear-gradient(90deg, #00cfff33, transparent)",
    marginBottom: 20,
  },
  aiText: {
    fontSize: 13, color: "#a0c0e0",
    lineHeight: 1.9, whiteSpace: "pre-wrap",
    letterSpacing: 0.3,
  },
  footer: {
    textAlign: "center", padding: "20px 48px",
    fontSize: 9, letterSpacing: 3,
    color: "#7a9ab544",
    borderTop: "1px solid #00ff9d11",
    position: "relative", zIndex: 1,
  },
};