import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    // If you want to proxy through Vite instead, uncomment:
    // proxy: {
    //   "/api": { target: "http://localhost:8080", changeOrigin: true, rewrite: (p) => p.replace(/^\/api/, "") }
    // }
  },
});
