import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// ReconForge serves the SPA from main.py:
//   GET /            -> ui/spa/index.html
//   GET /static/<f>  -> ui/spa/<f>   (flat dir only; subpaths are rejected)
// So we build a SINGLE flat app.js + app.css + index.html into ../ui/spa,
// referenced under /static/. No main.py changes, no runtime server dep.
export default defineConfig({
  plugins: [react()],
  base: "/static/",
  build: {
    outDir: "../ui/spa",
    emptyOutDir: true,
    assetsDir: "",
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
        entryFileNames: "app.js",
        chunkFileNames: "app-[name].js",
        assetFileNames: (info) =>
          info.name && info.name.endsWith(".css") ? "app.css" : "[name][extname]",
      },
    },
  },
});
