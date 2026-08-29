namespace SafeMe.Core.Models;

/// <summary>מצב האבטחה הכולל של החיבור, כפי שמוצג במגש המערכת.</summary>
public enum SecurityStatus
{
    /// <summary>אין מספיק נתונים / השירות זה עתה עלה.</summary>
    Unknown = 0,
    /// <summary>ירוק — חיבור מסונן ומאושר.</summary>
    Safe = 1,
    /// <summary>צהוב — סינון קיים אך חלקי.</summary>
    LowFilter = 2,
    /// <summary>אדום — חיבור לא מסונן / לא מזוהה.</summary>
    Unfiltered = 3,
    /// <summary>אפור — נעילת חירום פעילה, התעבורה חסומה.</summary>
    Blocked = 4
}

/// <summary>מצב האכיפה שהוגדר במדיניות.</summary>
public enum EnforcementMode
{
    Monitor = 0,
    Warn = 1,
    Enforce = 2
}

/// <summary>הפעולה שתבוצע כאשר הסטטוס אדום.</summary>
public enum RedAction
{
    None = 0,
    Warn = 1,
    Lockout = 2
}

/// <summary>רמת האמון בספק סינון מזוהה.</summary>
public enum TrustLevel
{
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3
}

/// <summary>תוצאת גשש בודד.</summary>
public enum ProbeOutcome
{
    Inconclusive = 0,
    Pass = 1,
    Fail = 2,

    /// <summary>
    /// נמצאה ראיה, אך לא כל מה שהגשש חיפש.
    ///
    /// שונה מכישלון: כישלון משמעו שהבדיקה רצה ולא מצאה דבר. כאן
    /// נמצא משהו אמיתי שאינו מספיק להכרעה מלאה, והוא זוכה לניקוד
    /// חלקי. בלי המצב הזה כל ראיה שאינה מלאה נספרה כאפס.
    /// </summary>
    Partial = 3
}

/// <summary>חומרת כשל של גשש.</summary>
public enum ProbeSeverity
{
    Info = 0,
    Warning = 1,
    Critical = 2
}

/// <summary>הציפייה מגשש תוכן: חסום או פתוח.</summary>
public enum ProbeExpectation
{
    Blocked = 0,
    Allowed = 1
}

/// <summary>שיטת אימות קוד ההסרה.</summary>
public enum UninstallKeyMode
{
    /// <summary>חתימת RSA-PSS מהשרת; המחשב מחזיק מפתח ציבורי בלבד (מומלץ).</summary>
    Rsa = 0,
    /// <summary>HMAC-SHA256 עם סוד מחשב; לשימוש אופליין בלבד.</summary>
    Hmac = 1
}

/// <summary>סוג אירוע חבלה שמדווח לשרת.</summary>
public enum TamperKind
{
    ServiceStopAttempt = 0,
    ServiceCrash = 1,
    TrayAppKilled = 2,
    WfpFiltersMissing = 3,
    StateFileMissing = 4,
    StateFileTampered = 5,
    ClockRolledBack = 6,
    PolicySignatureInvalid = 7,
    BfeUnavailable = 8,
    UninstallBruteForce = 9,

    /// <summary>
    /// המחשב היה דלוק והסוכן לא פעל.
    ///
    /// מתגלה בעלייה, מהשוואה בין יומן האירועים של Windows לבין
    /// מה שהסוכן דיווח. זהו האירוע היחיד שמתעד תקופה שבה התוכנה
    /// לא פעלה — כל שאר האירועים נרשמים בזמן שהיא כן פעלה.
    /// </summary>
    CoverageGap = 10
}
