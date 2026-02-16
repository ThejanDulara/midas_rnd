import React, { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

export default function Landing() {
  const [form, setForm] = useState({ email: "", phone: "", message: "" });

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.email || !form.message) {
      toast.warning("Please fill in email and message." , { containerId: "Landing" });
      return;
    }
    try {
      await api.post("/public/contact-admin", form);
      toast.success("Message sent to admin successfully!" , { containerId: "Landing" });
      setForm({ email: "", phone: "", message: "" });
    } catch (err) {
      console.error(err);
      toast.error("Failed to send message. Try again." , { containerId: "Landing" });
    }
  };

  return (
    <div
      style={{
        fontFamily: "sans-serif",
        backgroundColor: "#fff",
        color: "#2d3748",
        minHeight: "100vh",
      }}
    >

      {/* === Hero Section === */}
      <section
        style={{
          display: "flex",
          alignItems: "stretch",
          justifyContent: "center",
          width: "100%",
          minHeight: "85vh",
          padding: "60px 40px",
          boxSizing: "border-box",
          background: "linear-gradient(135deg, #3bb9af 0%, #b3dc39 100%)",
        }}
      >
        {/* Left Panel (with image + about) */}
        <div
          style={{
            flex: 1,
            background: "rgba(255,255,255,0.9)",
            borderRadius: "24px 0 0 24px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            color: "#2d3748",
            boxShadow: "0 8px 30px rgba(0,0,0,0.1)",
            padding: "40px 20px",
          }}
        >
          <img
            src="/AI.jpg"
            alt="AI illustration"
            style={{
              width: 280,
              height: 280,
              borderRadius: "50%",
              objectFit: "cover",
              border: "4px solid #3bb9af",
              marginBottom: 20,
              boxShadow: "0 4px 20px rgba(0,0,0,0.15)",
            }}
          />

          <h3
            style={{
              fontSize: 20,
              color: "#3bb9af",
              marginBottom: 10,
              fontWeight: 700,
            }}
          >
            About Research Hub
          </h3>
          <p
            style={{
              maxWidth: 500,
              fontSize: 18,
              lineHeight: 1.7,
              color: "#4a5568",
              textAlign: "center",
            }}
          >
            The Midas Media AI Research Hub is where innovation meets media
            intelligence. We focus on AI-driven research, data analytics, and
            automation to shape smarter, faster, and more efficient media
            strategies across the Sri Lankan advertising ecosystem.
          </p>
        </div>

        {/* Right Panel (title + buttons) */}
        <div
          style={{
            flex: 1,
            background: "#fff",
            borderRadius: "0 24px 24px 0",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 8px 30px rgba(0,0,0,0.08)",
            padding: "40px",
            textAlign: "center",
          }}
        >
          <h1
            style={{
              fontSize: 38,
              fontWeight: 700,
              marginBottom: 20,
              color: "#3bb9af",
            }}
          >
            Midas Media AI Research Hub
          </h1>
          <p style={{ fontSize: 20, color: "#4a5568", marginBottom: 40 }}>
            Smart media decisions powered by AI & Analytics.
          </p>

          <div style={{ display: "flex", justifyContent: "center", gap: 20 }}>
            <Link
              to="/signin"
              style={{
                background: "#3bb9af",
                color: "#fff",
                padding: "12px 24px",
                borderRadius: 10,
                textDecoration: "none",
                fontWeight: "bold",
                fontSize: 16,
              }}
            >
              Sign In
            </Link>
            <a
              href="#contact"
              style={{
                background: "#b3dc39",
                color: "#000",
                padding: "12px 24px",
                borderRadius: 10,
                textDecoration: "none",
                fontWeight: "bold",
                fontSize: 16,
              }}
            >
              Contact Admin
            </a>
          </div>
        </div>
      </section>

      {/* === Contact Admin Section (lighter gradient) === */}
      <section
        id="contact"
        style={{
          padding: "80px 20px",
          background: "linear-gradient(135deg, #e8faf8 0%, #f4fbdc 100%)",
          borderTop: "1px solid #e2e8f0",
        }}
      >
        <h2
          style={{
            textAlign: "center",
            fontSize: "36px",
            marginBottom: "40px",
            color: "#3bb9af",
            fontWeight: "700",
          }}
        >
          Contact Admin
        </h2>
        <form
          onSubmit={handleSubmit}
          style={{
            maxWidth: "600px",
            margin: "0 auto",
            display: "flex",
            flexDirection: "column",
            gap: "20px",
          }}
        >
          <input
            type="email"
            placeholder="Your Email"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            style={inputStyle}
            required
          />
          <input
            type="tel"
            placeholder="Your Phone Number (optional)"
            value={form.phone}
            onChange={(e) => setForm({ ...form, phone: e.target.value })}
            style={inputStyle}
          />
          <textarea
            placeholder="Your Message"
            value={form.message}
            onChange={(e) => setForm({ ...form, message: e.target.value })}
            style={{
              ...inputStyle,
              minHeight: 120,
              resize: "vertical",
            }}
            required
          />
          <button
            type="submit"
            style={{
              background: "#3bb9af",
              color: "#fff",
              padding: "14px",
              border: "none",
              borderRadius: 10,
              fontWeight: "bold",
              cursor: "pointer",
              fontSize: "16px",
            }}
          >
            Send Message
          </button>
        </form>
      </section>
    </div>
  );
}

const inputStyle = {
  padding: "14px",
  border: "1px solid #e2e8f0",
  borderRadius: "8px",
  fontSize: "16px",
  backgroundColor: "#fff",
  color: "#2d3748",
};
