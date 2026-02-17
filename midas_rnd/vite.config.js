import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8000", // ✅ LOCAL backend in dev
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: "localhost", // ✅ allow cookies in dev
      },
    },
  },
});
