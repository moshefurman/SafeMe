import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // הפורטל והשרת חולקים מקור אחד בפיתוח, כדי שעוגיית ההפעלה
    // תישלח כרגיל ולא תידרש הקלה של SameSite
    proxy: {
      "/api": { target: "http://127.0.0.1:3000", changeOrigin: false },
    },
  },
});
