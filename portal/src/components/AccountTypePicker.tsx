/**
 * בחירת סוג החשבון, עם ההסבר מה ההבדל.
 *
 * אותו רכיב בהרשמה, בהשלמת ההרשמה דרך Google ובהגדרות. שלושה מסכים
 * שכל אחד מנסח את ההבדל אחרת הם שלוש תשובות לאותה שאלה.
 *
 * ההבדל בין הסוגים אינו בהגנה, שזהה בכולם. הוא בשאלה מי הנאמן:
 * מי שמאשר הקלות והסרה. במשפחה ובארגון בעל החשבון הוא בדרך כלל
 * אדם אחר ממי שיושב מול המחשב, ולכן הוא עצמו הנאמן. בחשבון אישי
 * בעל החשבון הוא המשתמש, ולכן צריך נאמן נפרד (לשונית "נאמן").
 */

export type AccountType = "organization" | "family" | "individual";

export const ACCOUNT_TYPES: ReadonlyArray<{
  value: AccountType;
  label: string;
  what: string;
  trustee: string;
}> = [
  {
    value: "organization",
    label: "משרד או ארגון",
    what: "מחשבי עבודה, עם ניהול מרוכז וחלוקה לקבוצות.",
    trustee: "בעל החשבון הוא מנהל המשרד או איש המחשבים, והוא הנאמן. אפשר למנות נאמן נוסף מחוץ לארגון.",
  },
  {
    value: "family",
    label: "בית ומשפחה",
    what: "מחשבי הבית, לצד ספק הסינון שלכם.",
    trustee: "בעל החשבון הוא הנאמן: ההורה שפתח אותו מנהל את מחשבי הבית. אפשר גם למנות נאמן אחר.",
  },
  {
    value: "individual",
    label: "אישי",
    what: "המחשב שלי, בבית או בעבודה.",
    trustee:
      "בעל החשבון הוא גם המשתמש. כדי שההגנה תחזיק גם מולך, ממנים נאמן: אדם אחר שסומכים עליו, "
      + "שמאשר בדוא\"ל כל הקלה והסרה. ממנים אותו אחרי ההרשמה, בהגדרות, תחת \"נאמן\".",
  },
];

export const ACCOUNT_TYPE_LABEL: Record<string, string> = Object.fromEntries(
  ACCOUNT_TYPES.map((t) => [t.value, t.label]),
);

export function AccountTypePicker({
  value,
  onChange,
  disabled = false,
  name = "accountType",
}: {
  value: string;
  onChange: (next: AccountType) => void;
  disabled?: boolean;
  name?: string;
}): JSX.Element {
  return (
    <div className="acct-types" role="radiogroup" aria-label="סוג החשבון">
      {ACCOUNT_TYPES.map((type) => (
        <label key={type.value} className={value === type.value ? "acct-type on" : "acct-type"}>
          <input
            type="radio"
            name={name}
            value={type.value}
            checked={value === type.value}
            disabled={disabled}
            onChange={() => onChange(type.value)}
          />

          <span>
            <b>{type.label}</b>
            <span>{type.what}</span>

            {/* הנאמן מוסבר רק לסוג שנבחר, כדי ששלוש פסקאות לא יתחרו על העין */}
            {value === type.value && <span className="acct-trustee">{type.trustee}</span>}
          </span>
        </label>
      ))}

      <p className="muted small">
        ההגנה זהה בכל הסוגים. אפשר לשנות את סוג החשבון בכל עת, בהגדרות.
      </p>
    </div>
  );
}
