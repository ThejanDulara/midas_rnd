import React from "react";
import { useLocation, Link, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { api } from "../api";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

export default function SignIn() {
  const { signin } = useAuth();
  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [forgotOpen, setForgotOpen] = React.useState(false);
  const [otpSent, setOtpSent] = React.useState(false);
  const [otp, setOtp] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");

  // 🔹 Loading states
  const [isSigningIn, setIsSigningIn] = React.useState(false);
  const [isSendingOtp, setIsSendingOtp] = React.useState(false);
  const [isResettingPassword, setIsResettingPassword] = React.useState(false);

  const navigate = useNavigate();
  const params = new URLSearchParams(useLocation().search);
  const redirect = params.get("redirect") || "/dashboard";

  const onSubmit = async (e) => {
    e.preventDefault();

    // Prevent multiple clicks
    if (isSigningIn) return;

    setIsSigningIn(true);

    try {
      await signin(email, password);

      // ✅ decode redirect safely
      let decodedRedirect = redirect ? decodeURIComponent(redirect) : null;

      if (decodedRedirect && decodedRedirect.startsWith("http")) {
        window.location.href = decodedRedirect; // full URL (subdomain)
      } else {
        navigate(decodedRedirect || "/dashboard", { replace: true });
      }
    } catch (err) {
      const status = err.response?.status;
      const message = err.response?.data?.error || "Sign-in failed";

      if (status === 403) {
        toast.info("Your account is pending admin approval.", { containerId: "SignIn" });
      } else if (status === 401) {
        toast.error("Invalid credentials.", { containerId: "SignIn" });
      } else {
        toast.error(message);
      }
    } finally {
      setIsSigningIn(false);
    }
  };

  const sendOtp = async () => {
    // Prevent multiple clicks
    if (isSendingOtp) return;

    setIsSendingOtp(true);

    try {
      await api.post("/auth/forgot", { email });
      setOtpSent(true);
      toast.success("OTP sent. Check your email.", { containerId: "SignIn" });
    } catch {
      toast.error("Unable to send OTP", { containerId: "SignIn" });
    } finally {
      setIsSendingOtp(false);
    }
  };

  const resetPwd = async () => {
    // Prevent multiple clicks
    if (isResettingPassword) return;

    // ✅ Validate password strength before sending to backend
    const missing = [];
    if (!/[A-Z]/.test(newPassword)) missing.push("one capital letter");
    if (!/[0-9]/.test(newPassword)) missing.push("one number");
    if (!/[!@#$%^&*(),.?\":{}|<>]/.test(newPassword)) missing.push("one special character");
    if (newPassword.length < 8) missing.push("8 characters");

    if (missing.length > 0) {
      toast.warning(`Password must include ${missing.join(", ")}.`, { containerId: "SignIn" });
      return;
    }

    setIsResettingPassword(true);

    try {
      await api.post("/auth/reset", { email, otp, new_password: newPassword });
      toast.success("Password updated. Please sign in.", { containerId: "SignIn" });
      setForgotOpen(false);
      setOtpSent(false);
      setOtp("");
      setNewPassword("");
    } catch (e) {
      toast.error(e.response?.data?.error || "Reset failed", { containerId: "SignIn" });
    } finally {
      setIsResettingPassword(false);
    }
  };

  return (
    <>
      {/* === Full-page layout === */}
      <section style={pageWrapper}>
        {/* Left gradient panel */}
        <div style={leftPanel}>
          <div style={leftInner}>
            <img
              src="/TS-GARA-Mask.png"
              alt="TS GARA Mask"
              style={{
                height: 400,
                marginBottom: 30,
                filter: "drop-shadow(0 2px 6px rgba(0,0,0,0.2))",
              }}
            />
            <h1 style={leftTitle}>Media Intelligence Platform</h1>
            <p style={leftText}>
              Meet the Daredevils in the Media Scene Who Curate Hand Crafted Business Solutions By Harnessing the Power of Data Driven Local insights.
            </p>
          </div>
        </div>

        {/* Right form panel */}
        <div style={rightPanel}>
          <div style={formBox}>
            <div style={{ textAlign: "center", marginBottom: 28 }}>
              <div style={iconCircle}>🤖</div>
              <h2 style={formTitle}>Welcome Back</h2>
              <p style={formSubtitle}>
                Sign in to your Third Shift Media account
              </p>
            </div>

            <form onSubmit={onSubmit} style={{ display: "grid", gap: 20 }}>
              <div>
                <label style={labelStyle}>Email address</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  style={inputStyle}
                  placeholder="Enter your email"
                  disabled={isSigningIn}
                />
              </div>

              <div>
                <label style={labelStyle}>Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  style={inputStyle}
                  placeholder="Enter your password"
                  disabled={isSigningIn}
                />
              </div>

              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  fontSize: 14,
                }}
              >
                <label style={checkboxLabel}>
                  <input
                    type="checkbox"
                    style={{
                      width: 16,
                      height: 16,
                      accentColor: "#3bb9af", // ✅ brand green color
                      cursor: "pointer",
                    }}
                    disabled={isSigningIn}
                  />
                  Remember me
                </label>
                <button
                  type="button"
                  onClick={() => setForgotOpen(true)}
                  style={forgotLink}
                  disabled={isSigningIn}
                >
                  Forgot password?
                </button>
              </div>

              <button
                type="submit"
                style={{
                  ...primaryBtn,
                  opacity: isSigningIn ? 0.7 : 1,
                  cursor: isSigningIn ? "not-allowed" : "pointer",
                }}
                disabled={isSigningIn}
              >
                {isSigningIn ? "Signing In..." : "Sign In →"}
              </button>

              <div style={divider}></div>

              <p style={{ textAlign: "center", fontSize: 14, color: "#4a5568" }}>
                New to our platform?
              </p>
              <Link
                to="/signup"
                style={{
                  ...secondaryBtn,
                  pointerEvents: isSigningIn ? "none" : "auto",
                  opacity: isSigningIn ? 0.7 : 1,
                }}
              >
                Create an account
              </Link>
            </form>
          </div>
        </div>

        {/* Forgot password modal */}
        {forgotOpen && (
          <div style={modalBackdrop} onClick={() => !isSendingOtp && !isResettingPassword && setForgotOpen(false)}>
            <div style={modalBox} onClick={(e) => e.stopPropagation()}>
              <h3 style={{ marginTop: 0, color: "#1a202c", textAlign: "center" }}>
                Reset Password
              </h3>
              <p
                style={{
                  fontSize: 14,
                  color: "#4a5568",
                  textAlign: "center",
                  marginBottom: 20,
                }}
              >
                We'll send a 6-digit OTP to your email.
              </p>

              <div style={{ display: "grid", gap: 16 }}>
                <input
                  type="email"
                  placeholder="Your Email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  style={inputStyle}
                  disabled={isSendingOtp || isResettingPassword}
                />
                {!otpSent ? (
                  <button
                    onClick={sendOtp}
                    style={{
                      ...primaryBtn,
                      opacity: isSendingOtp ? 0.7 : 1,
                      cursor: isSendingOtp ? "not-allowed" : "pointer",
                    }}
                    disabled={isSendingOtp}
                  >
                    {isSendingOtp ? "Sending OTP..." : "Send OTP"}
                  </button>
                ) : (
                  <>
                    <input
                      placeholder="Enter OTP"
                      value={otp}
                      onChange={(e) => setOtp(e.target.value)}
                      style={inputStyle}
                      disabled={isResettingPassword}
                    />
                    {/* === New Password with Validation === */}
                    <div>
                      <input
                        type="password"
                        placeholder="New Password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        style={inputStyle}
                        disabled={isResettingPassword}
                      />

                      {/* Password validation messages */}
                      <ul style={validationList}>
                        {!/[A-Z]/.test(newPassword) && (
                          <li style={validationItem}>• Must include at least one capital letter</li>
                        )}
                        {!/[0-9]/.test(newPassword) && (
                          <li style={validationItem}>• Must include at least one number</li>
                        )}
                        {!/[!@#$%^&*(),.?":{}|<>]/.test(newPassword) && (
                          <li style={validationItem}>• Must include one special character</li>
                        )}
                        {newPassword.length < 8 && (
                          <li style={validationItem}>• Must be at least 8 characters long</li>
                        )}
                      </ul>
                    </div>

                    <button
                      onClick={resetPwd}
                      style={{
                        ...primaryBtn,
                        opacity: isResettingPassword ? 0.7 : 1,
                        cursor: isResettingPassword ? "not-allowed" : "pointer",
                      }}
                      disabled={isResettingPassword}
                    >
                      {isResettingPassword ? "Resetting..." : "Set New Password"}
                    </button>
                  </>
                )}
                <button
                  onClick={() => !isSendingOtp && !isResettingPassword && setForgotOpen(false)}
                  style={textBtnStyle}
                  disabled={isSendingOtp || isResettingPassword}
                >
                  Back to Sign In
                </button>
              </div>
            </div>
          </div>
        )}
      </section>
    </>
  );
}

/* === STYLES === */
const pageWrapper = {
  width: "100%",
  minHeight: "100vh",
  display: "flex",
  flexWrap: "wrap",       // optional: stack panels on small screens
  overflowY: "auto",
  background: "#fff",
};

/* Left gradient */
const leftPanel = {
  flex: 1,
  background: "linear-gradient(135deg, #3bb9af 0%, #b3dc39 100%)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  color: "#fff",
  padding: "60px 40px",
};
const leftInner = { textAlign: "center", maxWidth: 500 };
const leftTitle = { fontSize: 32, fontWeight: 700, marginBottom: 16 };
const leftText = { fontSize: 18, lineHeight: 1.6, color: "#000000" };

/* Right side */
const rightPanel = {
  flex: 1,
  background: "#f8fafc",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: "40px 20px",
};

const formBox = {
  background: "#fff",
  padding: "40px 36px",
  borderRadius: 16,
  boxShadow: "0 4px 25px rgba(0,0,0,0.06)",
  width: "100%",
  maxWidth: 400,
  border: "1px solid #e2e8f0",
};

const iconCircle = {
  width: 60,
  height: 60,
  borderRadius: "50%",
  backgroundColor: "#76cec7",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 28,
  margin: "0 auto 16px",
};

const formTitle = {
  fontSize: 24,
  fontWeight: 700,
  color: "#2d3748",
  marginBottom: 4,
};
const formSubtitle = {
  color: "#4a5568",
  fontSize: 14,
  margin: 0,
};

const labelStyle = {
  fontSize: 14,
  color: "#374151",
  fontWeight: 500,
  marginBottom: 4,
  display: "block",
};

const inputStyle = {
  padding: "12px 14px",
  border: "1px solid #d1d5db",
  borderRadius: 8,
  fontSize: 15,
  width: "100%",
  boxSizing: "border-box",
  outline: "none",
};

const forgotLink = {
  background: "none",
  border: "none",
  color: "#3bb9af",
  cursor: "pointer",
  fontWeight: 500,
};

const primaryBtn = {
  backgroundColor: "#3bb9af",
  color: "#fff",
  padding: "12px",
  border: "none",
  borderRadius: 8,
  fontSize: 15,
  fontWeight: 600,
  cursor: "pointer",
  transition: "all 0.2s",
};
const secondaryBtn = {
  background: "#fff",
  border: "1px solid #cbd5e1",
  color: "#3bb9af",
  padding: "12px",
  borderRadius: 8,
  textAlign: "center",
  textDecoration: "none",
  fontWeight: 600,
};

const divider = {
  height: 1,
  backgroundColor: "#e5e7eb",
  margin: "16px 0",
};

const modalBackdrop = {
  position: "fixed",
  inset: 0,
  background: "rgba(0,0,0,0.4)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  zIndex: 1000,
};

const modalBox = {
  background: "#fff",
  padding: "24px",
  borderRadius: 10,
  width: "90%",
  maxWidth: 380,
  boxShadow: "0 10px 40px rgba(0,0,0,0.2)",
};

const textBtnStyle = {
  background: "none",
  border: "none",
  color: "#4a5568",
  cursor: "pointer",
  fontSize: 14,
  padding: "8px",
};

const checkboxLabel = {
  display: "flex",
  alignItems: "center",
  gap: 6,
  fontSize: 14,
  color: "#2d3748", // darker gray for better visibility
  cursor: "pointer",
};

const validationList = {
  listStyleType: "none",
  paddingLeft: 10,
  marginTop: 6,
  marginBottom: 0,
  fontSize: 12,
  color: "#e53e3e", // red text
};

const validationItem = {
  marginBottom: 2,
};