import React from "react";
import { api } from "../api";
import { toast } from "react-toastify";

export default function Admin() {
  const [pending, setPending] = React.useState([]);
  const [allUsers, setAllUsers] = React.useState([]);

  // 🔹 Track loading states for each user+action
  const [actionLoading, setActionLoading] = React.useState({});

  const load = async () => {
    try {
      const [pendingRes, allRes] = await Promise.all([
        api.get("/admin/users?status=pending"),
        api.get("/admin/users"),
      ]);

      setPending(pendingRes.data);
      const approvedUsers = allRes.data.filter((u) => u.is_approved === 1);
      setAllUsers(approvedUsers);
    } catch (e) {
      console.error(e);
    }
  };

  React.useEffect(() => {
    load();
  }, []);

  const approve = async (id) => {
    // Create unique key for this action
    const actionKey = `${id}_approve`;

    // Prevent re-clicking if already loading
    if (actionLoading[actionKey]) return;

    try {
      // Set loading BEFORE API call
      setActionLoading(prev => ({ ...prev, [actionKey]: true }));

      // Remove the artificial sleep - let it show loading until API completes
      await api.post("/admin/approve", { user_id: id });

      toast.success("Approved & emailed user", { containerId: "Admin" });
      load();
    } catch (e) {
      toast.error("Approval failed", { containerId: "Admin" });
    } finally {
      // Clear loading state AFTER API completes (success or error)
      setActionLoading(prev => ({ ...prev, [actionKey]: false }));
    }
  };

  const reject = async (id) => {
    const actionKey = `${id}_reject`;

    if (actionLoading[actionKey]) return;

    try {
      setActionLoading(prev => ({ ...prev, [actionKey]: true }));
      await api.post("/admin/reject", { user_id: id });
      toast.info("User rejected", { containerId: "Admin" });
      load();
    } catch (e) {
      toast.error("Rejection failed", { containerId: "Admin" });
    } finally {
      setActionLoading(prev => ({ ...prev, [actionKey]: false }));
    }
  };

  const remove = async (id, isAdmin) => {
    if (isAdmin) return;

    const actionKey = `${id}_delete`;

    if (actionLoading[actionKey]) return;

    try {
      setActionLoading(prev => ({ ...prev, [actionKey]: true }));
      await api.delete(`/admin/users/${id}`);
      toast.info("Account deleted", { containerId: "Admin" });
      load();
    } catch (e) {
      toast.error("Delete failed", { containerId: "Admin" });
    } finally {
      setActionLoading(prev => ({ ...prev, [actionKey]: false }));
    }
  };

  // Helper to check if a specific action is loading
  const isLoading = (id, type) => {
    return actionLoading[`${id}_${type}`] || false;
  };

  return (
    <section style={pageWrapper}>
      <div style={container}>
        <h1 style={pageTitle}>Admin Dashboard — User Management</h1>

        {/* Pending Approvals */}
        <div style={card}>
          <h2 style={sectionTitle}>Pending Approvals</h2>
          {pending.length === 0 ? (
            <p style={emptyText}>No pending user approvals 🎉</p>
          ) : (
            <div style={tableWrapper}>
              <table style={table}>
                <thead>
                  <tr>
                    <th style={th}>Profile</th>
                    <th style={th}>Name</th>
                    <th style={th}>Email</th>
                    <th style={th}>Designation</th>
                    <th style={th}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {pending.map((u) => (
                    <tr key={u.id}>
                      <td style={td}>
                        <img
                          src={
                            u.profile_pic
                              ? `${import.meta.env.VITE_API_BASE_URL || "https://tsmbackend-production.up.railway.app"}${u.profile_pic}`
                              : "/static/default-avatar.png"
                          }
                          alt="Profile"
                          style={profilePic}
                        />
                      </td>
                      <td style={td}>{u.first_name} {u.last_name}</td>
                      <td style={td}>{u.email}</td>
                      <td style={td}>{u.designation || "-"}</td>
                      <td style={td}>
                        <button
                          onClick={() => approve(u.id)}
                          style={{
                            ...btnApprove,
                            opacity: isLoading(u.id, "approve") ? 0.6 : 1,
                          }}
                          disabled={isLoading(u.id, "approve")}
                        >
                          {isLoading(u.id, "approve") ? "Approving..." : "Approve"}
                        </button>

                        <button
                          onClick={() => reject(u.id)}
                          style={{
                            ...btnReject,
                            opacity: isLoading(u.id, "reject") ? 0.6 : 1,
                          }}
                          disabled={isLoading(u.id, "reject")}
                        >
                          {isLoading(u.id, "reject") ? "Rejecting..." : "Reject"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* All Users */}
        <div style={card}>
          <h2 style={sectionTitle}>All Approved Users</h2>
          {allUsers.length === 0 ? (
            <p style={emptyText}>No approved users yet.</p>
          ) : (
            <div style={tableWrapper}>
              <table style={table}>
                <thead>
                  <tr>
                    <th style={th}>Profile</th>
                    <th style={th}>Name</th>
                    <th style={th}>Email</th>
                    <th style={th}>Designation</th>
                    <th style={th}>Admin</th>
                    <th style={th}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {allUsers.map((u) => (
                    <tr key={u.id}>
                      <td style={td}>
                        <img
                          src={
                            u.profile_pic
                              ? `${import.meta.env.VITE_API_BASE_URL || "https://tsmbackend-production.up.railway.app"}${u.profile_pic}`
                              : "/static/default-avatar.png"
                          }
                          alt="Profile"
                          style={profilePic}
                        />
                      </td>
                      <td style={td}>{u.first_name} {u.last_name}</td>
                      <td style={td}>{u.email}</td>
                      <td style={td}>{u.designation || "-"}</td>
                      <td style={td}>{u.is_admin ? "Yes" : "No"}</td>
                      <td style={td}>
                        <button
                          onClick={() => remove(u.id, u.is_admin)}
                          style={{
                            ...btnDelete,
                            opacity: u.is_admin || isLoading(u.id, "delete") ? 0.4 : 1,
                            cursor: u.is_admin || isLoading(u.id, "delete") ? "not-allowed" : "pointer",
                          }}
                          disabled={u.is_admin || isLoading(u.id, "delete")}
                        >
                          {isLoading(u.id, "delete") ? "Deleting..." : "Delete"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

/* === STYLES === */
const pageWrapper = {
  width: "100%",
  minHeight: "100vh",
  backgroundColor: "#f8fafc",
  padding: "40px 0",
  display: "flex",
  justifyContent: "center",
};

const container = {
  width: "100%",
  maxWidth: 1200,
  padding: "0 24px",
  fontFamily:
    '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
};

const pageTitle = {
  fontSize: 28,
  fontWeight: 700,
  color: "#2d3748",
  marginBottom: 32,
  textAlign: "center",
};

const card = {
  background: "#fff",
  borderRadius: 16,
  boxShadow: "0 6px 20px rgba(0,0,0,0.06)",
  padding: "24px",
  marginBottom: 40,
  border: "1px solid #edf2f7",
};

const sectionTitle = {
  fontSize: 20,
  fontWeight: 600,
  color: "#3bb9af",
  marginBottom: 16,
};

const tableWrapper = {
  overflowX: "auto",
};

const table = {
  width: "100%",
  borderCollapse: "collapse",
};

const th = {
  textAlign: "left",
  padding: "12px",
  borderBottom: "2px solid #e2e8f0",
  fontSize: 14,
  color: "#4a5568",
  backgroundColor: "#f9fafc",
};

const td = {
  padding: "12px",
  borderBottom: "1px solid #edf2f7",
  fontSize: 14,
  color: "#2d3748",
  verticalAlign: "middle",
};

const profilePic = {
  width: 48,
  height: 48,
  borderRadius: "50%",
  objectFit: "cover",
  border: "1px solid #e2e8f0",
};

const emptyText = {
  color: "#718096",
  fontStyle: "italic",
  textAlign: "center",
  padding: "16px 0",
};

const btnApprove = {
  backgroundColor: "#3bb9af",
  color: "#fff",
  border: "none",
  padding: "6px 12px",
  borderRadius: 6,
  marginRight: 8,
  cursor: "pointer",
  fontSize: 14,
  fontWeight: 500,
};

const btnReject = {
  backgroundColor: "#b3dc39",
  color: "#000",
  border: "none",
  padding: "6px 12px",
  borderRadius: 6,
  cursor: "pointer",
  fontSize: 14,
  fontWeight: 500,
};

const btnDelete = {
  backgroundColor: "#e53e3e",
  color: "#fff",
  border: "none",
  padding: "6px 12px",
  borderRadius: 6,
  cursor: "pointer",
  fontSize: 14,
  fontWeight: 500,
};
