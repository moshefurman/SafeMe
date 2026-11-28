/**
 * בחירת סוג החשבון, עם ההסבר מה ההבדל.
 *
 * אותו רכיב בהרשמה, בהשלמת ההרשמה דרך Google ובהגדרות. שלושה מסכים
 * שכל אחד מנסח את ההבדל אחרת הם שלוש תשובות לאותה שאלה.
 *
 * ההבדל בין הסוגים אינו בהגנה, שזהה בכולם. הוא בשאלה מי הנאמן:
 * מי שמחזיק את המפתח, ויכול להקל הגדרות, לאשר רשתות ולהנפיק קוד
 * הסרה. היום הנאמן הוא מי שמחזיק בכניסה לחשבון, ולכן השאלה היא
 * מי האדם הזה ביחס למי שיושב מול המחשב.
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
    trustee: "הנאמן הוא מנהל המשרד או איש המחשבים, ולא העובד שיושב מול המחשב.",
  },
  {
    value: "family",
    label: "בית ומשפחה",
    what: "מחשבי הבית, לצד ספק הסינון שלכם.",
    trustee: "הנאמן הוא בעל החשבון: ההורה שפתח אותו מנהל את מחשבי הילדים.",
  },
  {
    value: "individual",
    label: "אישי",
    what: "המחשב שלי, בבית או בעבודה.",
    trustee:
      "בעל החשבון הוא גם המשתמש. כדי שההגנה תחזיק גם מולך, הנאמן צריך להיות מישהו אחר: "
      + "אדם שאתה סומך עליו שיחזיק את הכניסה לחשבון, או המוקד שלנו (בוחרים בהתקנה \"הסרה רק דרך המוקד\").",
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
