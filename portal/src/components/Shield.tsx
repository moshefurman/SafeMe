import { useId } from "react";

import type { SecurityStatus } from "../types";

/**
 * מחוון המצב: המגן של Filter+ בצבע ובסימן של מצב המחשב.
 *
 * הצללית היא זו של המגן שבלוגו (assets/filterplus-mark.svg) — חוד
 * עליון, כתפיים קעורות, קשת אחת אל הקודקוד. המסלול זהה לזה של
 * ShieldRenderer.BuildShieldPath ב-C#, באותה מערכת קואורדינטות של
 * 0..100, כך שהמחוון בפורטל זהה לאייקון המגש ולתג הצף.
 *
 * הלוגו עצמו — עם המשפך ובלי מצב — הוא רכיב Logo.
 */

const SHIELD =
  "M 10,14.2 Q 29.9,13.4 50,4 Q 70.1,13.4 90,14.2 " +
  "L 90,48.6 Q 90,76.4 50,96 Q 10,76.4 10,48.6 Z";

/**
 * הפלוס של הלוגו, בפינה הימנית העליונה. שני מלבנים מעוגלים.
 *
 * כמו ב-C#: רק מגודל 48 ומעלה, בצבע המגן, ועם רווח שקוף סביבו.
 * בגדלים קטנים הוא נדבק לסימן המצב והופך לכתם.
 */
const PLUS_MIN_SIZE = 48;
const PLUS = { cx: 84, cy: 20, arm: 13, half: 3.4, gap: 3.2 };

function PlusBars({ grow, fill }: { grow: number; fill: string }) {
  const h = PLUS.half + grow;
  const a = PLUS.arm + grow;

  return (
    <>
      <rect x={PLUS.cx - h} y={PLUS.cy - a} width={2 * h} height={2 * a} rx={h} fill={fill} />
      <rect x={PLUS.cx - a} y={PLUS.cy - h} width={2 * a} height={2 * h} rx={h} fill={fill} />
    </>
  );
}

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

  const maskId = useId();
  const withPlus = size >= PLUS_MIN_SIZE;

  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      {withPlus && (
        <mask id={maskId}>
          <rect width="100" height="100" fill="#fff" />
          <PlusBars grow={PLUS.gap} fill="#000" />
        </mask>
      )}
      <g mask={withPlus ? `url(#${maskId})` : undefined}>
        <path d={SHIELD} fill={fill} />
        <path d={SHIELD} fill="none" stroke="rgba(255,255,255,0.28)" strokeWidth="2" />
      </g>
      {withPlus && <PlusBars grow={0} fill={fill} />}
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
