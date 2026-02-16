import React, { createContext, useEffect, useState, useContext } from "react";
import { api } from "./api";

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // ✅ Fetch current user (if cookie exists)
  useEffect(() => {
    api
      .get("/auth/me")
      .then((res) => setUser(res.data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

const signin = async (email, password) => {
  const res = await api.post("/auth/signin", { email, password });
  // temporarily set basic info
  setUser(res.data);

  // ✅ Fetch full profile immediately after login
  try {
    const { data } = await api.get("/auth/me");
    setUser(data); // replace with complete info
  } catch {
    console.warn("Could not refresh user profile after login");
  }
};


  const signout = async () => {
    await api.post("/auth/signout");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, setUser, loading, signin, signout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
