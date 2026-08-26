import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export const LOCAL_API = "http://127.0.0.1:3000";

/**
 * הפורטל והשרת חולקים מקור אחד מבחינת הדפדפן, דרך proxy.
 *
 * זה נותן שני דברים: עוגיית ההפעלה נשלחת כרגיל בלי להקל על
 * SameSite, ואין צורך ב-CORS בשרת בכלל.
 */
export function portalConfig(target: string) {
  return defineConfig({
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": {
          target,
          // מול שרת מרוחק חובה להחליף את כותרת המארח, אחרת הוא
          // רואה בקשה ל-localhost ומסרב
          changeOrigin: target.startsWith("https://"),
          secure: true,
        },
      },
    },
  });
}

export default portalConfig(LOCAL_API);
