import { useAuth } from "./AuthContext";
import { Navigate, Outlet } from "react-router-dom";

export default function ProtectedRoute({ adminOnly = false }) {
  const { user, loading } = useAuth();

  if (loading) return null; // wait until /auth/me finishes
  if (!user) return <Navigate to="/signin" replace />;
  if (adminOnly && !user.is_admin) return <Navigate to="/dashboard" replace />;

  return <Outlet />;
}
