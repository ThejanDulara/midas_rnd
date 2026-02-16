import React from "react";
import { api } from "../api";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

export default function SignUp() {
  const [form, setForm] = React.useState({
    first_name: "",
    last_name: "",
    designation: "",
    email: "",
    password: "",
    confirm: "",
  });
  const [file, setFile] = React.useState(null);
  const [preview, setPreview] = React.useState(null);
  const [passwordErrors, setPasswordErrors] = React.useState([]);
  const [isSubmitting, setIsSubmitting] = React.useState(false); // 🔹 Loading state
  const navigate = useNavigate();

  // ✅ Password validation
  const validatePassword = (password) => {
    const errors = [];
    if (password.length < 8) errors.push("At least 8 characters");
    if (!/[A-Z]/.test(password)) errors.push("At least one uppercase letter");
    if (!/[0-9]/.test(password)) errors.push("At least one number");
    if (!/[!@#$%^&*(),.?\":{}|<>]/.test(password))
      errors.push("At least one special character");
    return errors;
  };

  const onChange = (e) => {
    const { name, value } = e.target;
    setForm({ ...form, [name]: value });

    if (name === "password") {
      setPasswordErrors(validatePassword(value));
    }
  };

  const onFileChange = (e) => {
    const selected = e.target.files[0];
    setFile(selected);
    if (selected) {
      const reader = new FileReader();
      reader.onloadend = () => setPreview(reader.result);
      reader.readAsDataURL(selected);
    } else {
      setPreview(null);
    }
  };

  const onSubmit = async (e) => {
    e.preventDefault();

    // Prevent multiple submissions
    if (isSubmitting) return;

    // ✅ Check password match and strength
    if (form.password !== form.confirm) {
      toast.error("Passwords do not match", { containerId: "SignUp" });
      return;
    }
    const errors = validatePassword(form.password);
    if (errors.length > 0) {
      toast.error("Please meet all password requirements", { containerId: "SignUp" });
      setPasswordErrors(errors);
      return;
    }

    const fd = new FormData();
    Object.entries(form).forEach(([k, v]) => {
      if (k !== "confirm") fd.append(k, v);
    });
    if (file) fd.append("profile_pic", file);

    setIsSubmitting(true);

    try {
      await api.post("/auth/signup", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      toast.success(
        "Application submitted! Your account is under review. You'll receive an email once approved.",
        { containerId: "SignUp" }
      );
      setTimeout(() => navigate("/signin"), 4000);
    } catch (e) {
      toast.error(e.response?.data?.error || "Sign-up failed", { containerId: "SignUp" });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <section style={pageWrapper}>
        {/* Left gradient panel */}
        <div style={leftPanel}>
          <div style={leftInner}>
            <img
              src="/MTM.png"
              alt="MTM"
              style={{
                height: 500,
                filter: "drop-shadow(0 2px 6px rgba(0,0,0,0.2))",
              }}
            />
            <h1 style={leftTitle}>Join Midas Media</h1>
            <p style={leftText}>
              Be a part of Sri Lanka's leading AI-driven media intelligence team.
              Let's build smarter insights and meaningful media solutions together.
            </p>
          </div>
        </div>

        {/* Right form panel */}
        <div style={rightPanel}>
          <div style={formBox}>
            <div style={{ textAlign: "center", marginBottom: 24 }}>
              <div style={iconCircle}>📋</div>
              <h2 style={formTitle}>Create Account</h2>
              <p style={formSubtitle}>
                Join Midas Media AI Research Hub
              </p>
            </div>

            <form onSubmit={onSubmit} style={{ display: "grid", gap: 16 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <input
                  name="first_name"
                  placeholder="First name"
                  value={form.first_name}
                  onChange={onChange}
                  required
                  style={{
                    ...inputStyle,
                    opacity: isSubmitting ? 0.7 : 1,
                    cursor: isSubmitting ? "not-allowed" : "text",
                  }}
                  disabled={isSubmitting}
                />
                <input
                  name="last_name"
                  placeholder="Last name"
                  value={form.last_name}
                  onChange={onChange}
                  required
                  style={{
                    ...inputStyle,
                    opacity: isSubmitting ? 0.7 : 1,
                    cursor: isSubmitting ? "not-allowed" : "text",
                  }}
                  disabled={isSubmitting}
                />
              </div>

              <input
                name="designation"
                placeholder="Designation"
                value={form.designation}
                onChange={onChange}
                style={{
                  ...inputStyle,
                  opacity: isSubmitting ? 0.7 : 1,
                  cursor: isSubmitting ? "not-allowed" : "text",
                }}
                disabled={isSubmitting}
              />

              <input
                name="email"
                type="email"
                placeholder="Email address"
                value={form.email}
                onChange={onChange}
                required
                style={{
                  ...inputStyle,
                  opacity: isSubmitting ? 0.7 : 1,
                  cursor: isSubmitting ? "not-allowed" : "text",
                }}
                disabled={isSubmitting}
              />

              <div>
                <input
                  name="password"
                  type="password"
                  placeholder="Password"
                  value={form.password}
                  onChange={onChange}
                  required
                  style={{
                    ...inputStyle,
                    opacity: isSubmitting ? 0.7 : 1,
                    cursor: isSubmitting ? "not-allowed" : "text",
                  }}
                  disabled={isSubmitting}
                />
                {/* ✅ Password validation feedback */}
                {passwordErrors.length > 0 && (
                  <ul style={passwordHintList}>
                    {passwordErrors.map((err, i) => (
                      <li key={i} style={passwordHintItem}>❌ {err}</li>
                    ))}
                  </ul>
                )}
              </div>

              <input
                name="confirm"
                type="password"
                placeholder="Confirm password"
                value={form.confirm}
                onChange={onChange}
                required
                style={{
                  ...inputStyle,
                  opacity: isSubmitting ? 0.7 : 1,
                  cursor: isSubmitting ? "not-allowed" : "text",
                }}
                disabled={isSubmitting}
              />

              {/* File Upload */}
              <div style={{ display: "grid", gap: 8 }}>
                <label style={{
                  fontSize: 14,
                  color: "#4a5568",
                  fontWeight: 500,
                  opacity: isSubmitting ? 0.7 : 1
                }}>
                  Profile picture (optional)
                </label>
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  {preview ? (
                    <img
                      src={preview}
                      alt="Preview"
                      style={{
                        width: 56,
                        height: 56,
                        borderRadius: "50%",
                        objectFit: "cover",
                        border: "2px solid #e2e8f0",
                        opacity: isSubmitting ? 0.7 : 1,
                      }}
                    />
                  ) : (
                    <div
                      style={{
                        width: 56,
                        height: 56,
                        borderRadius: "50%",
                        backgroundColor: "#f7fafc",
                        border: "2px dashed #e2e8f0",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "#718096",
                        fontSize: 12,
                        opacity: isSubmitting ? 0.7 : 1,
                      }}
                    >
                      No image
                    </div>
                  )}

                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <label
                      htmlFor="profileUpload"
                      style={{
                        backgroundColor: "#f9fafc",
                        border: "1px solid #d1d5db",
                        borderRadius: 8,
                        padding: "8px 12px",
                        color: "#000",
                        cursor: isSubmitting ? "not-allowed" : "pointer",
                        fontSize: 14,
                        fontWeight: 500,
                        opacity: isSubmitting ? 0.7 : 1,
                      }}
                    >
                      Choose File
                    </label>
                    <input
                      id="profileUpload"
                      type="file"
                      accept="image/*"
                      onChange={onFileChange}
                      style={{ display: "none" }}
                      disabled={isSubmitting}
                    />
                    <span style={{
                      color: "#000",
                      fontSize: 13,
                      opacity: isSubmitting ? 0.7 : 1
                    }}>
                      {file ? file.name : "No file chosen"}
                    </span>
                  </div>
                </div>
              </div>

              <button
                type="submit"
                style={{
                  ...primaryBtn,
                  opacity: isSubmitting ? 0.7 : 1,
                  cursor: isSubmitting ? "not-allowed" : "pointer",
                }}
                disabled={isSubmitting}
              >
                {isSubmitting ? "Submitting..." : "Submit for Approval"}
              </button>
            </form>

            <p
              style={{
                marginTop: 20,
                textAlign: "center",
                fontSize: 14,
                color: "#718096",
                opacity: isSubmitting ? 0.7 : 1,
              }}
            >
              Already have an account?{" "}
              <Link
                to="/signin"
                style={{
                  color: "#3bb9af",
                  textDecoration: "none",
                  fontWeight: 500,
                  pointerEvents: isSubmitting ? "none" : "auto",
                }}
              >
                Sign in
              </Link>
            </p>
          </div>
        </div>
      </section>
    </>
  );
}

/* === STYLES === */
const pageWrapper = {
  width: "100%",
  minHeight: "100vh",
  display: "flex",
  flexWrap: "wrap",
  background: "#fff",
  position: "relative",
  overflow: "hidden",
};

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
const leftText = { fontSize: 18, lineHeight: 1.6, color: "#000" };

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
  maxWidth: 460,
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

const inputStyle = {
  padding: "12px 14px",
  border: "1px solid #d1d5db",
  borderRadius: 8,
  fontSize: 15,
  width: "100%",
  boxSizing: "border-box",
  outline: "none",
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

const passwordHintList = {
  listStyle: "none",
  margin: "6px 0 0 0",
  padding: 0,
  fontSize: 13,
  color: "#b91c1c",
};
const passwordHintItem = {
  marginBottom: 2,
};