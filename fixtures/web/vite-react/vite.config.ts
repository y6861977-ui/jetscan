import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// NEGATIVE (WEB-SECRET-001): the config runs in Node at build time.
const DEPLOY_TOKEN = "@@GITHUB_TOKEN@@";

export default defineConfig({
  plugins: [react()],
  server: { headers: { "x-deploy": DEPLOY_TOKEN.slice(0, 0) } },
  // POSITIVE (WEB-DEBUG-007) line 12: public source maps in the production build.
  // NEGATIVE: css.devSourcemap is dev-only.
  build: { sourcemap: true },
  css: { devSourcemap: true },
});
