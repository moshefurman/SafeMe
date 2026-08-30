namespace SafeMe.Core.Updates;

/// <summary>מה לעשות עם מה שכבר יושב על הדיסק.</summary>
public enum ResumeAction
{
    /// <summary>להתחיל מאפס. אין קובץ, או שמה שיש בו חסר משמעות.</summary>
    StartOver,

    /// <summary>להמשיך מהמקום שבו נעצר, בבקשת Range.</summary>
    Resume,

    /// <summary>הקובץ כבר מלא. נותר רק לאמת אותו.</summary>
    Complete
}

/// <summary>
/// מאיפה להמשיך הורדה שנקטעה.
///
/// נבנה אחרי שהתברר בשטח שהורדה של שישים ואחת מגה מקו סלולרי נופלת
/// באמצע, ומאבדת את הכול. עם אלפי התקנות, חלקן על קווים חלשים, זה
/// אינו מקרה קצה: יש מחשבים שלעולם לא ישלימו הורדה רציפה, ויישארו
/// על גרסה ישנה בלי שאיש יידע.
///
/// הכשל הזה שקט במיוחד — הוא נראה בדיוק כמו מחשב שאין לו עדכון.
///
/// ההכרעה מופרדת מהקלט/פלט כדי שאפשר יהיה לבדוק אותה, ובעיקר את
/// המקרים שאין דרך לייצר אותם בשטח: קובץ ארוך מהמוצהר, קובץ ריק,
/// וקובץ שכבר שלם.
/// </summary>
public readonly record struct ResumePlan(ResumeAction Action, long From)
{
    /// <summary>
    /// כמה כבר יש, וכמה צריך.
    ///
    /// אורך שלילי או גודל לא חוקי נופלים להתחלה מאפס. אין כאן
    /// זריקת חריגה: זו החלטה על קובץ זמני, ומחיקה והתחלה מחדש היא
    /// תמיד תשובה בטוחה.
    /// </summary>
    public static ResumePlan For(long existingBytes, long expectedBytes)
    {
        if (expectedBytes <= 0) return new ResumePlan(ResumeAction.StartOver, 0);

        if (existingBytes <= 0) return new ResumePlan(ResumeAction.StartOver, 0);

        if (existingBytes == expectedBytes) return new ResumePlan(ResumeAction.Complete, existingBytes);

        /*
         * ארוך מהמוצהר.
         *
         * לא ייתכן מהורדה תקינה, ולכן מה שיש שם אינו מה שאנחנו
         * חושבים. אפשרות אחת היא קובץ שנשאר משחרור אחר עם אותו
         * שם; אחרת היא מישהו שכתב לתיקייה הזמנית. בשני המקרים
         * המשך ממנו היה בונה קובץ שאיננו יודעים מה הוא.
         *
         * הגיבוב היה תופס את זה בסוף בכל מקרה, אבל רק אחרי הורדה
         * שלמה נוספת. עדיף למחוק עכשיו.
         */
        if (existingBytes > expectedBytes) return new ResumePlan(ResumeAction.StartOver, 0);

        return new ResumePlan(ResumeAction.Resume, existingBytes);
    }
}
