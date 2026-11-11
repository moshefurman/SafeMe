import type { SecurityStatus } from "../types";

/**
 * המגן של SafeMe.
 *
 * מסלול ה-SVG הוא תרגום מדויק של ShieldRenderer.BuildShieldPath ב-C#,
 * באותה מערכת קואורדינטות של 0..100. כך הצורה בפורטל זהה לזו שבאייקון
 * התוכנה, באייקון המגש ובתג הצף.
 */

const SHIELD =
  "M 8,15 A 10,10 0 0 1 18,5 L 82,5 A 10,10 0 0 1 92,15 " +
  "L 92,32 C 92,62 78,81 50,96 C 22,81 8,62 8,32 Z";

/**
 * הסימן שבתוך המגן משתנה לפי המצב, ובמכוון.
 *
 * וי אומר "נבדק ותקין". מגן אדום עם וי לבן אומר את שני הדברים
 * בבת אחת, והעין קולטת את הווי. משתמש שמעיף מבט לפינת המסך היה
 * מסיק שהכול בסדר בדיוק כשזה לא.
 *
 * כל המסלולים באותה מערכת קואורדינטות 0..100 כמו המגן, ומשוכפלים
 * ב-ShieldRenderer בצד ה-C# — אותו סימן באייקון, במגש ובתג הצף.
 */
const MARKS: Record<SecurityStatus, string[]> = {
  // וי
  safe: ["M 31,52 L 43,64 L 69,36"],
  // סימן קריאה: הסינון נחלש
  low_filter: ["M 50,30 L 50,56", "M 50,68 L 50,69"],
  // איקס: אין סינון
  unfiltered: ["M 35,37 L 65,67", "M 65,37 L 35,67"],
  // מקף: הגישה חסומה
  blocked: ["M 33,52 L 67,52"],
  // שלוש שורות, האחרונה קצרה: רשימה. רק מה שכתוב בה נפתח.
  whitelist: ["M 35,39 L 65,39", "M 35,53 L 65,53", "M 35,67 L 54,67"],
  // סימן שאלה מקוצר: עוד לא ידוע
  unknown: ["M 39,42 A 11,11 0 1 1 50,55 L 50,60", "M 50,70 L 50,71"],
};

export const STATUS_COLOR: Record<SecurityStatus, string> = {
  safe: "#22a058",
  low_filter: "#d68e0c",
  unfiltered: "#ce382e",
  blocked: "#6b7480",
  /*
   * סגול רגוע לרשימה לבנה. תואם ל---whitelist ב-styles.css.
   *
   * לא ירוק: ירוק אומר "ספק סינון מאושר זוהה", וזה לא מה שקורה
   * כאן. לא אדום ולא כתום: המחשב מוגן, ובמצב המחמיר ביותר שיש.
   * גוון שאינו על הסולם ירוק־כתום־אדום אומר "מצב אחר", וזה נכון.
   */
  whitelist: "#9a86e0",
  unknown: "#8c96a3",
};

export function Shield({
  status,
  size = 22,
  color,
}: {
  status?: SecurityStatus;
  size?: number;
  color?: string;
}) {
  /*
   * שני שימושים שונים לאותו רכיב, וצריך להבחין ביניהם.
   *
   * מחוון מצב מקבל status ומצייר את הסימן שמתאים לו. שימוש מיתוגי
   * — בסרגל, במסכי הכניסה, בכותרת התחתונה — מקבל צבע מפורש בלי
   * מצב, ושם הסימן הוא תמיד וי: זה הלוגו ולא מחוון, ולוגו עם סימן
   * שאלה קורא "משהו לא ידוע".
   */
  const effective: SecurityStatus = status ?? (color ? "safe" : "unknown");
  const fill = color ?? STATUS_COLOR[effective];

  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      <path d={SHIELD} fill={fill} />
      <path d={SHIELD} fill="none" stroke="rgba(255,255,255,0.28)" strokeWidth="2" />
      {size >= 18 &&
        MARKS[effective].map((d) => (
          <path
            key={d}
            d={d}
            fill="none"
            stroke="#fff"
            strokeWidth="9"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        ))}
    </svg>
  );
}
