import React from "react";
import { api } from "../api";
import { useAuth } from "../AuthContext";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

export default function Profile() {
  const { user, setUser } = useAuth();
  const [form, setForm] = React.useState({
    first_name: "",
    last_name: "",
    designation: "",
  });
  const [oldP, setOldP] = React.useState("");
  const [newP, setNewP] = React.useState("");
  const [confirmP, setConfirmP] = React.useState("");
  const [file, setFile] = React.useState(null);
  const [preview, setPreview] = React.useState(null);

  React.useEffect(() => {
    if (user) {
      setForm({
        first_name: user.first_name || "",
        last_name: user.last_name || "",
        designation: user.designation || "",
      });
      if (user.profile_pic)
        setPreview(
          `${import.meta.env.VITE_API_BASE_URL || "https://mtmbackend-production.up.railway.app"}${user.profile_pic}`
        );
    }
  }, [user]);

  const saveProfile = async () => {
    try {
      await api.post("/user/profile", form);
      toast.success("Profile updated", { containerId: "profile" });
      const { data } = await api.get("/auth/me");
      setUser(data);
    } catch {
      toast.error("Failed to update profile", { containerId: "profile" });
    }
  };

  const onFileChange = (e) => {
    const selected = e.target.files[0];
    setFile(selected);
    if (selected) {
      const reader = new FileReader();
      reader.onloadend = () => setPreview(reader.result);
      reader.readAsDataURL(selected);
    }
  };

  const uploadPic = async () => {
    if (!file) {
      toast.warning("Please select a picture first", { containerId: "profile" });
      return;
    }
    const fd = new FormData();
    fd.append("profile_pic", file);
    try {
      const { data } = await api.post("/user/profile-picture", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      toast.success("Profile picture updated", { containerId: "profile" });
      setUser({ ...user, profile_pic: data.profile_pic });
    } catch {
      toast.error("Upload failed", { containerId: "profile" });
    }
  };

  const changePassword = async () => {
    if (!oldP || !newP || !confirmP) {
      toast.warning("All fields are required", { containerId: "profile" });
      return;
    }
    if (newP !== confirmP) {
      toast.error("New passwords do not match", { containerId: "profile" });
      return;
    }
    if (newP.length < 6) {
      toast.warning("Password must be at least 6 characters", { containerId: "profile" });
      return;
    }

    try {
      await api.post("/user/change-password", {
        old_password: oldP,
        new_password: newP,
        confirm_password: confirmP,
      });
      setOldP("");
      setNewP("");
      setConfirmP("");
      toast.success("Password changed successfully", { containerId: "profile" });
    } catch (e) {
      toast.error(e.response?.data?.error || "Failed to change password", { containerId: "profile" });
    }
  };

  if (!user) return null;

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
                height: 400,
                marginBottom: 30,
                filter: "drop-shadow(0 2px 6px rgba(0,0,0,0.2))",
              }}
            />
            <h1 style={leftTitle}>Your Media Profile</h1>
            <p style={leftText}>
              Manage your account details and credentials. Keep your information
              up to date to stay connected with the MTM Group Media AI Research Hub.
            </p>
          </div>
        </div>

        {/* Right panel */}
        <div style={rightPanel}>
          <div style={formBox}>
            <div style={{ textAlign: "center", marginBottom: 24 }}>
                {user.profile_pic ? (
                  <img
                    src={`${import.meta.env.VITE_API_BASE_URL || "https://mtmbackend-production.up.railway.app"}${user.profile_pic}`}
                    alt="Profile"
                    style={headerImg}
                  />
                ) : (
                  <div style={iconCircle}>👤</div>
                )}
              <h2 style={formTitle}>
                {user.first_name} {user.last_name}
              </h2>
              <p style={formSubtitle}>Profile Settings</p>
            </div>

            {/* Profile Info */}
            <div style={{ display: "grid", gap: 16 }}>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: 12,
                }}
              >
                <input
                  style={inputStyle}
                  placeholder="First name"
                  value={form.first_name}
                  onChange={(e) =>
                    setForm({ ...form, first_name: e.target.value })
                  }
                />
                <input
                  style={inputStyle}
                  placeholder="Last name"
                  value={form.last_name}
                  onChange={(e) =>
                    setForm({ ...form, last_name: e.target.value })
                  }
                />
              </div>

              <input
                style={inputStyle}
                placeholder="Designation"
                value={form.designation}
                onChange={(e) =>
                  setForm({ ...form, designation: e.target.value })
                }
              />

              <button style={primaryBtn} onClick={saveProfile}>
                Save Profile
              </button>
            </div>

            {/* Profile Picture */}
            <div style={{ marginTop: 32 }}>
              <h3 style={sectionTitle}>Profile Picture</h3>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                {preview ? (
                  <img
                    src={preview}
                    alt="Preview"
                    style={{
                      width: 64,
                      height: 64,
                      borderRadius: "50%",
                      objectFit: "cover",
                      border: "2px solid #e2e8f0",
                    }}
                  />
                ) : (
                  <div
                    style={{
                      width: 64,
                      height: 64,
                      borderRadius: "50%",
                      backgroundColor: "#f7fafc",
                      border: "2px dashed #e2e8f0",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: "#718096",
                      fontSize: 12,
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
                      cursor: "pointer",
                      fontSize: 14,
                      fontWeight: 500,
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
                  />
                  <span
                    style={{
                      color: "#000",
                      fontSize: 13,
                      maxWidth: 120,
                      overflow: "hidden",
                      whiteSpace: "nowrap",
                      textOverflow: "ellipsis",
                      display: "inline-block",
                      verticalAlign: "middle",
                    }}
                  >
                    {file ? file.name : "No file chosen"}
                  </span>
                </div>

                <button style={secondaryBtn} onClick={uploadPic}>
                  Upload New
                </button>
              </div>
            </div>

            {/* Change Password */}
            <div style={{ marginTop: 40 }}>
              <h3 style={sectionTitle}>Change Password</h3>
              <div style={{ display: "grid", gap: 14 }}>
                <input
                  type="password"
                  style={inputStyle}
                  placeholder="Current password"
                  value={oldP}
                  onChange={(e) => setOldP(e.target.value)}
                />
                <input
                  type="password"
                  style={inputStyle}
                  placeholder="New password"
                  value={newP}
                  onChange={(e) => setNewP(e.target.value)}
                />
                <input
                  type="password"
                  style={inputStyle}
                  placeholder="Confirm new password"
                  value={confirmP}
                  onChange={(e) => setConfirmP(e.target.value)}
                />
                <button style={primaryBtn} onClick={changePassword}>
                  Change Password
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>
    </>
  );
}

/* === STYLES === */
const pageWrapper = {
  width: "100%",
  minHeight: "100vh",   // ✅ allow full height
  display: "flex",
  overflowX: "hidden",  // ✅ only hide horizontal scroll
  background: "#fff",
  position: "relative",
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
  maxWidth: 480,
  border: "1px solid #e2e8f0",
  height: "fit-content",       // ✅ Let content decide height
  maxHeight: "120vh",           // ✅ Increase visible space
  overflowY: "auto",           // ✅ Allow gentle scroll only if necessary
  scrollbarWidth: "none",      // ✅ Hide scrollbar (Firefox)
  msOverflowStyle: "none",     // ✅ Hide scrollbar (IE/Edge)
};

const iconCircle = {
  width: 70,
  height: 70,
  borderRadius: "50%",
  backgroundColor: "#76cec7",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 28,
  margin: "0 auto 16px",
};

const headerImg = {
  width: 80,
  height: 80,
  borderRadius: "50%",
  objectFit: "cover",
  border: "2px solid #3bb9af",
  marginBottom: 12,
};

const formTitle = {
  fontSize: 22,
  fontWeight: 700,
  color: "#2d3748",
  marginBottom: 4,
};
const formSubtitle = { color: "#4a5568", fontSize: 14, margin: 0 };

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

const secondaryBtn = {
  backgroundColor: "#b3dc39",
  color: "#000",
  padding: "10px 14px",
  border: "none",
  borderRadius: 8,
  fontWeight: 600,
  cursor: "pointer",
  fontSize: 15,
};

const sectionTitle = {
  fontSize: 16,
  fontWeight: 600,
  color: "#3bb9af",
  marginBottom: 8,
};
