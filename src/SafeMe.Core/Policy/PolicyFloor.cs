using SafeMe.Core.Models;

namespace SafeMe.Core.Policy;

/// <summary>
/// רצפת המדיניות: רמת ההחמרה המינימלית שהמכשיר אוכף.
///
/// נקבעת ברישום המכשיר ונשלחת אליו חתומה. מעליה בעל הדייר חופשי לנוע
/// בשני הכיוונים (ארגז החול), ורק ירידה מתחתיה דורשת היתר חתום מהחברה.
/// </summary>
public sealed class PolicyFloorSpec
{
    public EnforcementMode Mode { get; set; } = EnforcementMode.Enforce;
    public RedAction OnRedAction { get; set; } = RedAction.Lockout;
    public int MinScoreForGreen { get; set; } = 85;
    public int MinScoreForYellow { get; set; } = 60;
    public List<string> RequireProvider { get; set; } = new();

    public PolicyStrictness ToStrictness() =>
        PolicyStrictness.Floor(Mode, OnRedAction, MinScoreForGreen, MinScoreForYellow, RequireProvider);

    /// <summary>ברירת מחדל מוקשחת, בשימוש כשעדיין לא התקבלה רצפה מהשרת.</summary>
    public static PolicyFloorSpec Default => new();
}

/// <summary>תוכן המעטפה החתומה שמכילה את הרצפה. נשלח ב-/enroll.</summary>
public sealed class PolicyFloorEnvelope
{
    /// <summary>מזהה החומרה שהרצפה שייכת לו. רצפה של מכשיר אחר נדחית.</summary>
    public string Hwid { get; set; } = "";

    public PolicyFloorSpec Floor { get; set; } = new();

    public DateTimeOffset IssuedUtc { get; set; }
}

/// <summary>
/// היתר להורדת הרצפה. חד-פעמי, קשור למכשיר יחיד, ובעל חלון זמן קצר.
///
/// נחתם במפתח נפרד מזה של המדיניות: מפתח המדיניות בשימוש תדיר, ומפתח
/// ההקלות נדיר ומוגן יותר. פריצה לשירות שמפרסם מדיניות אינה מקנה
/// יכולת להוריד רצפות.
/// </summary>
public sealed class LooseningGrant
{
    /// <summary>שמונת הבתים הראשונים של SHA256(HWID), בהקסה.</summary>
    public string HwidHash { get; set; } = "";

    /// <summary>מזהה חד-פעמי. שימוש חוזר נדחה.</summary>
    public string Nonce { get; set; } = "";

    public DateTimeOffset IssuedUtc { get; set; }
    public DateTimeOffset ExpiresUtc { get; set; }

    public PolicyFloorSpec FromFloor { get; set; } = new();
    public PolicyFloorSpec ToFloor { get; set; } = new();

    public string? ApprovedBy { get; set; }
    public string? Reason { get; set; }
}

public enum GrantValidation
{
    Ok = 0,
    HwidMismatch = 1,
    Expired = 2,
    NotYetValid = 3,
    AlreadyUsed = 4,
    /// <summary>ההיתר מתיימר לרדת מרצפה שאינה הרצפה הנוכחית של המכשיר.</summary>
    FloorMismatch = 5,
    /// <summary>ההיתר למעשה מחמיר, ולכן אינו נדרש ומעורר חשד.</summary>
    NotALoosening = 6,
    /// <summary>למכשיר לא הוגדר מפתח היתרים כלל.</summary>
    KeyMissing = 7,
    /// <summary>מפתח ההיתרים זהה למפתח המדיניות — ההפרדה אינה קיימת.</summary>
    KeyNotSeparate = 8
}

public sealed record GrantResult
{
    public GrantValidation Status { get; init; }
    public string Message { get; init; } = "";
    public bool Ok => Status == GrantValidation.Ok;
}

public static class LooseningGrantValidator
{
    /// <summary>סבילות לסטיית שעון בין המכשיר לשרת.</summary>
    public static readonly TimeSpan ClockTolerance = TimeSpan.FromMinutes(5);

    /// <summary>
    /// בודק שמפתח ההיתרים נפרד ממפתח המדיניות.
    ///
    /// זו כל ההגנה מאחורי "להחמיר כן, להסיר לא". בלעדיה, כל יכולת
    /// לחתום מדיניות היא גם יכולת להקל אותה מתחת לרצפה — ושרת שנפרץ,
    /// או שרת מזויף שהמכשיר הופנה אליו, היה יכול פשוט לשלוח את אותו
    /// מפתח בשני השדות.
    ///
    /// הסוכן אוכף זאת בעצמו ואינו מסתמך על כך שהשרת אכף.
    /// </summary>
    public static GrantResult CheckKeySeparation(string? looseningKeyPem, string? policyKeyPem) =>
        Security.KeySeparation.Check(looseningKeyPem, policyKeyPem) switch
        {
            Security.KeySeparationStatus.Missing => new GrantResult
            {
                Status = GrantValidation.KeyMissing,
                Message = "לא הוגדר מפתח היתרים למכשיר."
            },
            Security.KeySeparationStatus.NotSeparate => new GrantResult
            {
                Status = GrantValidation.KeyNotSeparate,
                Message = "מפתח ההיתרים זהה למפתח המדיניות. ההפרדה היא תנאי לקבלת הקלה."
            },
            _ => new GrantResult { Status = GrantValidation.Ok }
        };

    /// <summary>
    /// מאמת היתר הקלה מול המכשיר והרצפה הנוכחית שלו.
    /// אימות החתימה מתבצע לפני כן, ב-SignedEnvelopeReader.
    /// </summary>
    public static GrantResult Validate(
        LooseningGrant grant,
        string hwid,
        PolicyFloorSpec currentFloor,
        IReadOnlyCollection<string> usedNonces,
        DateTimeOffset? nowUtc = null)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(currentFloor);

        var now = nowUtc ?? DateTimeOffset.UtcNow;

        var expectedHash = Convert.ToHexString(Security.UninstallChallenge.ComputeHwidHash(hwid));

        if (!string.Equals(grant.HwidHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            return new GrantResult
            {
                Status = GrantValidation.HwidMismatch,
                Message = "ההיתר הונפק עבור מכשיר אחר."
            };

        if (now > grant.ExpiresUtc + ClockTolerance)
            return new GrantResult
            {
                Status = GrantValidation.Expired,
                Message = "פג תוקף ההיתר."
            };

        if (now < grant.IssuedUtc - ClockTolerance)
            return new GrantResult
            {
                Status = GrantValidation.NotYetValid,
                Message = "חותמת הזמן של ההיתר עתידית."
            };

        if (usedNonces.Contains(grant.Nonce, StringComparer.OrdinalIgnoreCase))
            return new GrantResult
            {
                Status = GrantValidation.AlreadyUsed,
                Message = "ההיתר כבר נוצל."
            };

        // ההיתר חייב לצאת מהרצפה הנוכחית בפועל. אחרת אפשר היה לשמור
        // היתר ישן ולהחיל אותו אחרי שהרצפה כבר הועלתה.
        var fromDelta = StrictnessComparer.Compare(
            currentFloor.ToStrictness(), grant.FromFloor.ToStrictness());

        var toCurrent = StrictnessComparer.Compare(
            grant.FromFloor.ToStrictness(), currentFloor.ToStrictness());

        if (fromDelta.IsLoosening || toCurrent.IsLoosening)
            return new GrantResult
            {
                Status = GrantValidation.FloorMismatch,
                Message = "ההיתר אינו מתאים לרצפה הנוכחית של המכשיר."
            };

        var delta = StrictnessComparer.Compare(currentFloor.ToStrictness(), grant.ToFloor.ToStrictness());

        if (!delta.IsLoosening)
            return new GrantResult
            {
                Status = GrantValidation.NotALoosening,
                Message = "ההיתר אינו מקל דבר. החמרה אינה דורשת היתר."
            };

        return new GrantResult { Status = GrantValidation.Ok, Message = "ההיתר תקף." };
    }
}
