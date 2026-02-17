import axios from "axios";

// Dynamically choose backend based on environment
const baseURL =
  import.meta.env.MODE === "development"
    ? "/api" // handled by Vite proxy (goes to localhost:8000)
    : "https://tsmbackend-production.up.railway.app/api"; // 👈 replace with your actual Railway backend URL

export const api = axios.create({
  baseURL,
  withCredentials: true, // send cookies (for login sessions)
});

// ✅ Handle 401 errors gracefully — no auto redirect
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      console.warn("⚠️ Not authenticated — returning 401 to caller");
      // Let AuthContext or ProtectedRoute handle logout/redirect
    }
    return Promise.reject(error);
  }
);
