import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const BACKEND_PORT = process.env.SG_HTTP_PORT ?? "8765";
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: BACKEND_URL,
        changeOrigin: false,
        secure: false,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    emptyOutDir: true,
  },
});
