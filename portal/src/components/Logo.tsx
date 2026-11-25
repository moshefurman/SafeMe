/**
 * סמל המותג: המגן והמשפך של Filter+ על אריח כחול כהה.
 *
 * נפרד מ-Shield במכוון. Shield הוא מחוון מצב — הצבע והסימן שבו
 * משתנים לפי מה שקורה במחשב. הלוגו אינו משתנה לעולם, ועירוב של
 * השניים ברכיב אחד הוא מה שגרם בעבר ללוגו להופיע עם סימן שאלה.
 *
 * הקובץ הוא assets/filterplus-mark.svg: אותו סמל של אייקון התוכנה,
 * וקטורי, ולכן חד בכל גודל ובכל צפיפות פיקסלים.
 */
export function Logo({ size = 26 }: { size?: number }) {
  return (
    <img
      src="/logo-mark.svg"
      width={size}
      height={size}
      alt=""
      aria-hidden="true"
      style={{ display: "block", flex: "none" }}
    />
  );
}
