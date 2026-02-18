import React, { useState, useEffect } from "react";
import { useAuth } from "../AuthContext";
import MediaCarousel from "./MediaCarousel";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const tools = [
  { name:'Communication Objective Prioritization Tool', url:'https://copt.midasmedialk.agency/', icon:'🧠', description:'Data-driven prioritization engine for communication strategies' },
  { name:'Campaign Touchpoint Scorer', url:'https://cts.midasmedialk.agency/', icon:'📊', description:'Campaign Touchpoint Prioritization via Weighted Communication Task Scoring' },
  { name:'Television Media Scheduling Optimization Tool', url:'https://opt.midasmedialk.agency/', icon:'🤖', description:'Smart media spot allocator using mathematical optimization' },
  { name:'Multimedia Reach Analyzer', url:'https://mmmr.midasmedialk.agency/', icon:'📈', description:'ML & genetic algorithm-based optimization for media mix' },
  { name:'Media Objective Identifier', url:'https://mo.midasmedialk.agency/', icon:'🧮', description:'Filtering media objectives to streamline decision-making' },
  { name:'Television Media Reach Predictor', url:'https://tmrp.midasmedialk.agency/', icon:'📺', description:'ML-based TV reach prediction for smarter planning' },
  { name:'Power BI Dashboards', url:'https://pbi.midasmedialk.agency/', icon:'📊', description:'Centralized library of Power BI dashboards' },
  { name:'Project Management tool', url:'https://pm.midasmedialk.agency/', icon:'🗃️', description:'Manage all projects in one centralized workspace' },
  { name:'Joseph W. Ostrow – Frequency Estimator ', url:'https://fe.midasmedialk.agency/', icon:'📐️', description:'Frequency planning tool based on the Ostrow model for effective reach optimization' },
  { name:'SOV/SOM Based Budget Planning tool', url:'https://bp.midasmedialk.agency/', icon:'🎯', description:'Manage all projects in one centralized workspace' },
  { name:'Coming Soon', url:'https://www.midasmedialk.agency/dashboard', icon:'✨', description:'AI-driven modules currently under development' },
];

export default function Dashboard() {
  const [hoveredCard, setHoveredCard] = useState(null);
  const [media, setMedia] = useState([]);
  const { user } = useAuth();

  useEffect(() => {
    fetch("/ai-highlights/manifest.json", { cache: "no-store" })
      .then((r) => r.json())
      .then(setMedia)
      .catch((err) => console.error("Failed to load manifest:", err));
  }, []);

  return (
    <div style={styles.pageWrapper}>
      {/* Toast Notifications */}
      <ToastContainer position="top-right" autoClose={4000} theme="light" style={{ zIndex: 9999 }} />

      {/* Header Section */}
      <section style={styles.heroSection}>
        <div style={styles.heroInner}>
          <div style={styles.heroIcon}>🤖</div>
          <h1 style={styles.heroTitle}>
            Welcome{user ? `, ${user.first_name}` : ""} to the{" "}
            <span style={{ color: "#3bb9af" }}>Midas Media AI Research Hub</span>
          </h1>
          <p style={styles.heroText}>
            Smart media decisions powered by <strong>AI</strong> and{" "}
            <strong>Analytics</strong>.
          </p>
        </div>
      </section>

      {/* Tools Section */}
      <section style={styles.toolsSection}>
        <h2 style={styles.sectionTitle}>Explore Our Tools</h2>
        <div style={styles.cardGrid}>
          {tools.map((tool, i) => (
            <a
              key={i}
              href={tool.url}
              target="_blank"
              rel="noopener noreferrer"
              className={`tool-card ${hoveredCard === i ? "hovered" : ""}`}
              onMouseEnter={() => setHoveredCard(i)}
              onMouseLeave={() => setHoveredCard(null)}
              style={{
                ...styles.toolCard,
                transform: hoveredCard === i ? "translateY(-6px)" : "none",
                boxShadow:
                  hoveredCard === i
                    ? "0 10px 25px rgba(59,185,175,0.2)"
                    : "0 4px 12px rgba(0,0,0,0.06)",
              }}
            >
              <div style={styles.toolIcon}>{tool.icon}</div>
              <div style={styles.toolContent}>
                <h3 style={styles.toolName}>{tool.name}</h3>
                <p style={styles.toolDescription}>{tool.description}</p>
              </div>
            </a>
          ))}
        </div>
      </section>

      {/* Media Highlights */}
      <section style={styles.mediaSection}>
        <h2 style={styles.sectionTitle}>AI Research Highlights</h2>
        <div style={styles.videoWrapper}>
          {media.length > 0 ? (
            <MediaCarousel media={media} intervalMs={5000} />
          ) : (
            <div style={styles.placeholder}>
              <div style={styles.playButton}>▶</div>
              <p>AI Research Highlights</p>
            </div>
          )}
        </div>
      </section>

      {/* Footer Message */}
      <p style={styles.footer}>
        ⚡ This is just the beginning — more intelligent tools are on their way...
      </p>
    </div>
  );
}

/* === STYLES === */
const styles = {
  pageWrapper: {
    background: "linear-gradient(135deg, #f7fafc 0%, #e6f8f5 100%)",
    minHeight: "100vh",
    padding: "40px 20px",
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  },

  heroSection: {
    textAlign: "center",
    marginBottom: "50px",
  },
  heroInner: {
    background: "white",
    borderRadius: 20,
    boxShadow: "0 8px 30px rgba(0,0,0,0.08)",
    padding: "40px 30px",
    maxWidth: 900,
    margin: "0 auto",
    border: "1px solid #edf2f7",
  },
  heroIcon: {
    fontSize: 50,
    marginBottom: 10,
  },
  heroTitle: {
    fontSize: 28,
    fontWeight: 700,
    color: "#2d3748",
    marginBottom: 8,
  },
  heroText: {
    color: "#4a5568",
    fontSize: 16,
  },

  toolsSection: {
    margin: "60px auto",
    maxWidth: 1200,
    textAlign: "center",
  },
  sectionTitle: {
    fontSize: 22,
    fontWeight: 700,
    color: "#3bb9af",
    marginBottom: 24,
  },
  cardGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
    gap: 24,
    justifyItems: "center",
  },
  toolCard: {
    background: "#fff",
    borderRadius: 16,
    textDecoration: "none",
    color: "#2d3748",
    padding: "24px 20px",
    width: "100%",
    maxWidth: 360,
    transition: "all 0.3s ease",
    display: "flex",
    alignItems: "center",
    gap: 16,
    border: "1px solid #edf2f7",
  },
  toolIcon: {
    fontSize: 30,
    background: "#e8f9f7",
    color: "#3bb9af",
    borderRadius: 12,
    padding: 16,
    flexShrink: 0,
  },
  toolContent: { textAlign: "left" },
  toolName: {
    fontSize: 16,
    fontWeight: 600,
    margin: "0 0 6px 0",
    color: "#2d3748",
  },
  toolDescription: {
    fontSize: 14,
    color: "#4a5568",
    margin: 0,
  },

  mediaSection: {
    marginTop: 80,
    textAlign: "center",
  },
  videoWrapper: {
    maxWidth: 900,
    margin: "0 auto",
    borderRadius: 16,
    overflow: "hidden",
    boxShadow: "0 8px 30px rgba(0,0,0,0.1)",
    aspectRatio: "16/9",
    background: "linear-gradient(135deg, #3bb9af 0%, #b3dc39 100%)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  placeholder: {
    color: "#fff",
    textAlign: "center",
  },
  playButton: {
    fontSize: 48,
    cursor: "pointer",
    marginBottom: 10,
    transition: "transform 0.2s",
  },
  footer: {
    marginTop: 50,
    textAlign: "center",
    color: "#3bb9af",
    fontStyle: "italic",
    fontWeight: 500,
  },
};
