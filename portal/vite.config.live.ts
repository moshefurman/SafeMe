import { portalConfig } from "./vite.config.ts";

/**
 * הפורטל מקומית, מול השרת שנפרס.
 *
 *   npm run dev:live
 *
 * קובץ נפרד ולא משתנה סביבה, כי הטבעת משתנים בשורת הפקודה אינה
 * עובדת אותו דבר ב-PowerShell וב-bash, וזה לא המקום להיתקע בו.
 */
export default portalConfig("https://safeme-h7h4.onrender.com");
