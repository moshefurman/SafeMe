namespace SafeMe.Core.Security;

/// <summary>תוצאת בדיקת הפרדה בין מפתח כפוף למפתח המדיניות.</summary>
public enum KeySeparationStatus
{
    Ok = 0,
    /// <summary>למכשיר לא הוגדר המפתח הכפוף כלל.</summary>
    Missing = 1,
    /// <summary>המפתח הכפוף זהה למפתח המדיניות — ההפרדה אינה קיימת.</summary>
    NotSeparate = 2
}

/// <summary>
/// כל מפתח הוא סמכות אחת: לחתום מדיניות, להקל אותה, או להסיר מכשיר.
///
/// ההפרדה ביניהם היא מה שמונע ממי שהשיג סמכות אחת לקבל גם את
/// האחרות. שרת שנפרץ ומסוגל לחתום מדיניות אינו אמור להיות מסוגל
/// בכך גם להקל אותה מתחת לרצפה, ולא להנפיק קוד הסרה למכשיר כלשהו.
///
/// הסוכן אוכף את זה בעצמו ואינו מסתמך על כך שהשרת אכף. שרת מזויף
/// שהמכשיר הופנה אליו יכול לשלוח את אותו מפתח בכל השדות.
/// </summary>
public static class KeySeparation
{
    public static KeySeparationStatus Check(string? subordinateKeyPem, string? policyKeyPem)
    {
        if (string.IsNullOrWhiteSpace(subordinateKeyPem))
            return KeySeparationStatus.Missing;

        // אין מפתח מדיניות להשוואה: מכשיר שנרשם מול שרת ישן. שאר
        // האימותים עדיין חלים, ולכן אין סיבה לחסום אותו כאן.
        if (string.IsNullOrWhiteSpace(policyKeyPem))
            return KeySeparationStatus.Ok;

        return string.Equals(
            NormalizePem(subordinateKeyPem),
            NormalizePem(policyKeyPem),
            StringComparison.Ordinal)
            ? KeySeparationStatus.NotSeparate
            : KeySeparationStatus.Ok;
    }

    /// <summary>
    /// משווה PEM בלי להיתלות ברווחים ובסופי שורה. אותו מפתח שהגיע
    /// משני נתיבים עלול להיבדל בעטיפה בלבד, והשוואה נאיבית הייתה
    /// מכריזה עליו כשונה — וההפרדה הייתה נראית קיימת בזמן שאינה.
    /// </summary>
    public static string NormalizePem(string pem) =>
        new([.. pem.Where(c => !char.IsWhiteSpace(c))]);
}
