using SafeMe.Core.Policy;
using SafeMe.Core.Security;

namespace SafeMe.Core.Models;

public sealed class EnrollRequest
{
    public required string Hwid { get; set; }
    public string MachineName { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public string AgentVersion { get; set; } = "";

    /// <summary>
    /// אסימון רישום שמונפק מהפורטל. מקודד את הדייר ואת פרופיל ההתקנה,
    /// חד-פעמי או מוגבל-שימושים, ופג תוקף. מחליף את מפתח הרישיון הישן,
    /// שהיה קבוע ולכן ניתן לשכפול בין מחשבים.
    /// </summary>
    public string? EnrollToken { get; set; }

    /// <summary>
    /// איך יהיה אפשר להסיר את התוכנה: "self_service" או "support_only".
    ///
    /// נבחר בהתקנה ולא בפורטל, כי זה הרגע שבו ההורה מחליט. ביקור
    /// עתידי בפורטל הוא רגע אחר לגמרי — הוא כבר לא עומד מול המחשב,
    /// וכבר לא בהלך הרוח שבו קנה את המוצר.
    ///
    /// השרת מחיל אותו רק אם טרם נבחר. התקנה שנייה באותו חשבון אינה
    /// דרך לשנות את ההגדרה, ולכן ריק כאן אינו משנה דבר.
    /// </summary>
    public string? UninstallPolicy { get; set; }

    /// <summary>
    /// הרף המתירני ביותר שהחשבון ירשה לעצמו במדיניות הרשתות:
    /// "strict", "balanced" או "lenient".
    ///
    /// נבחר בהתקנה מאותה סיבה כמו הגדרת ההסרה — זה הרגע שבו ההורה
    /// מחליט, והוא צלול. ביקור עתידי בפורטל הוא רגע אחר לגמרי:
    /// ההגבלה כבר מפריעה לו, וזה בדיוק כשההחלטה צריכה להחזיק.
    ///
    /// השרת מחיל אותו רק אם טרם נקבע, ולכן התקנה שנייה אינה דרך
    /// לעקוף את מה שנקבע בראשונה.
    /// </summary>
    public string? NetworkFloor { get; set; }

    public Guid InstallId { get; set; }
}

public sealed class EnrollResponse
{
    public Guid DeviceId { get; set; }
    public string DeviceToken { get; set; } = "";
    public string? PolicyEtag { get; set; }
    public UninstallKeyMode UninstallKeyMode { get; set; } = UninstallKeyMode.Rsa;

    /// <summary>מפתח ציבורי של השרת (PEM) לאימות קודי הסרה ולאימות חתימת מדיניות.</summary>
    public string? ServerPublicKeyPem { get; set; }

    /// <summary>
    /// מפתח ציבורי נפרד לאימות קודי הסרה בלבד.
    ///
    /// ההסרה חייבת לעבור דרך החברה. כל עוד הקוד מאומת במפתח
    /// המדיניות, מי שמשיג את היכולת לחתום מדיניות מקבל גם את
    /// היכולת להסיר כל מחשב — ושתי הסמכויות האלה לא אמורות
    /// לנסוע יחד.
    /// </summary>
    public string? UninstallPublicKeyPem { get; set; }

    /// <summary>
    /// המפתח שמאמת הצעות עדכון.
    ///
    /// השרת שלח אותו מאז שמנגנון העדכון נבנה; הסוכן פשוט לא הכיר
    /// את השדה ולכן זרק אותו. זו הסיבה שהעדכון האוטומטי לא עבד
    /// למרות ששני הצדדים היו כתובים.
    /// </summary>
    public string? UpdatePublicKeyPem { get; set; }

    /// <summary>
    /// מפתח ציבורי נפרד לאימות היתרי הקלה בלבד.
    ///
    /// ההפרדה היא כל ההגנה מאחורי "להחמיר כן, להסיר לא": שרת שנפרץ
    /// ומסוגל לחתום מדיניות אינו מסוגל בכך גם להקל אותה מתחת לרצפה.
    /// אם הוא זהה למפתח המדיניות, ההיתר נדחה.
    /// </summary>
    public string? LooseningPublicKeyPem { get; set; }

    /// <summary>סוד מחשב, מאוכלס רק כאשר UninstallKeyMode הוא Hmac.</summary>
    public string? DeviceSecret { get; set; }

    /// <summary>family_child, individual או organization.</summary>
    public string? InstallProfile { get; set; }

    /// <summary>
    /// מצב האכיפה ההתחלתי, נקבע בהתקנה. העלאתו מרחוק מותרת,
    /// הורדתו דורשת היתר הקלה חתום. ראה 3.2 באפיון.
    /// </summary>
    public EnforcementMode EnforcementMode { get; set; } = EnforcementMode.Enforce;

    /// <summary>רצפת המדיניות, חתומה. המחשב מאמת ושומר אותה מוגנת.</summary>
    public SignedEnvelope? PolicyFloor { get; set; }

    public string? SigningKid { get; set; }

    public DateTimeOffset? LicenseExpiresUtc { get; set; }
}

public sealed class NetworkAdapterInfo
{
    public string Name { get; set; } = "";
    public string? Ssid { get; set; }
    public string? Gateway { get; set; }
    public string? LocalIp { get; set; }
    public string? Description { get; set; }

    /// <summary>
    /// כתובת החומרה של השער.
    ///
    /// כתובת השער היא מספר שאפשר לשנות בהגדרות; כתובת החומרה
    /// מזוהה ליצרן. שילוב השניים הוא מה שמבדיל בין נתב ביתי
    /// לבין טלפון שמשתף אינטרנט.
    /// </summary>
    public string? GatewayMac { get; set; }

    /// <summary>true אם המתאם נראה כמתאם VPN וירטואלי (TAP, WinTun, WireGuard).</summary>
    public bool IsVirtualVpn { get; set; }
}

public sealed class HeartbeatRequest
{

    public required string Hwid { get; set; }
    public string AgentVersion { get; set; } = "";
    public int PolicyVersion { get; set; }
    public DateTimeOffset SentUtc { get; set; } = DateTimeOffset.UtcNow;
    public long Sequence { get; set; }
    public SecurityStatus Status { get; set; }
    public int Score { get; set; }
    public EnforcementMode Enforcement { get; set; }
    public List<NetworkAdapterInfo> ActiveAdapters { get; set; } = new();
    public string? PublicIp { get; set; }
    public string? DetectedProvider { get; set; }

    /// <summary>
    /// ספק האינטרנט שמאחורי הרשת — מזהה ASN.
    ///
    /// נשלח כדי שאישור רשת לא ייגרר לספק אחר: אותו נתב, אותו שם,
    /// וקו אחר מאחוריו. null פירושו שלא הצלחנו לקרוא, ולא שאין ספק.
    /// </summary>
    public string? IspKey { get; set; }

    /// <summary>שם הספק, לתצוגה בלבד. אין השוואה מולו.</summary>
    public string? IspName { get; set; }
    public List<string> FailedProbes { get; set; } = new();
    public List<TamperEvent> TamperEvents { get; set; } = new();
    public int WfpFilterCount { get; set; }
    public long UptimeSec { get; set; }
    public bool LockoutActive { get; set; }

    /// <summary>
    /// מזהי היתרי ההקלה שהמחשב כבר החיל.
    ///
    /// השרת מעדכן את הרצפה הרשומה אצלו רק לפי הרשימה הזו, ולא ברגע
    /// ההנפקה: הסוכן הוא שמאמת את ההיתר ורשאי לדחות אותו, ורצפה
    /// שנרשמה כמונמכת בשרת בעוד המחשב סירב הייתה מונעת כל היתר
    /// עתידי — כי כולם היו יוצאים מרצפה שאינה קיימת.
    /// </summary>
    public List<string> AppliedGrantNonces { get; set; } = new();
}

public sealed class HeartbeatResponse
{
    public bool Ok { get; set; }
    public DateTimeOffset ServerUtc { get; set; }
    public string? PolicyEtag { get; set; }
    public DateTimeOffset? LicenseExpiresUtc { get; set; }
    public bool LicenseValid { get; set; } = true;
    public List<RemoteCommand> Commands { get; set; } = new();

    /// <summary>ההכרעה על הרשת שהמחשב מחובר אליה. null כשאין מתאם.</summary>
    public NetworkVerdict? Network { get; set; }

    /// <summary>
    /// הצעת עדכון, כמעטפה חתומה. null כשאין מה להציע.
    ///
    /// היא מגיעה חתומה ולא כטקסט פשוט מסיבה אחת: היא ההיתר היחיד
    /// שבגללו הסוכן מוריד קובץ מהאינטרנט ומריץ אותו כ-SYSTEM. שרת
    /// שנפרץ, או שרת מזויף שהמחשב הופנה אליו, אינו יכול לייצר
    /// אותה בלי המפתח.
    /// </summary>
    public SignedEnvelope? Update { get; set; }

    /// <summary>
    /// היתר להורדת רצפת המדיניות, חתום במפתח ההיתרים. null כרגיל.
    ///
    /// כל מנגנון האימות היה בנוי בסוכן — הפרדת מפתחות, nonce חד-פעמי,
    /// תוקף, והתאמה לרצפה הנוכחית — ומעולם לא היה מי שיקרא לו,
    /// מפני שלא הייתה דרך להעביר היתר. הצד הקשה היה גמור והצינור
    /// חסר.
    ///
    /// מגיע בפעימה כמו הצעת העדכון, ומאותה סיבה: זה הערוץ היחיד
    /// שכל מחשב עובר בו תמיד, ומחשב כבוי פשוט יקבל כשיחזור.
    /// </summary>
    public SignedEnvelope? LooseningGrant { get; set; }

    /// <summary>
    /// מצב קוד ההסרה, כשהשרת משדרג אותו. null בפעימה רגילה.
    ///
    /// המצב נקבע ברישום, והתקנה מעל התקנה קיימת אינה נרשמת מחדש —
    /// EnsureEnrolledAsync יוצא מיד כשיש אסימון. כלומר מחשב שנרשם
    /// לפני שהשרת ידע לגזור סודות היה נשאר בקוד הארוך לנצח, ואיש
    /// לא היה מגלה עד השיחה הראשונה למוקד שאי אפשר לסיים.
    ///
    /// הפעימה היא המקום היחיד שכל מחשב עובר בו תמיד, ולכן השדרוג
    /// כאן. השרת שולח פעם אחת ומפסיק.
    /// </summary>
    public UninstallKeyMode? UninstallKeyMode { get; set; }

    /// <summary>סוד המחשב, מגיע יחד עם השדרוג ל-Hmac בלבד.</summary>
    public string? DeviceSecret { get; set; }
}

/// <summary>
/// תוכן הצעת העדכון, אחרי אימות החתימה.
///
/// כל שדה כאן הוא תנאי שנבדק לפני ההרצה, ולא מידע לתצוגה.
/// </summary>
public sealed class UpdateOffer
{
    public string Version { get; set; } = "";
    public string DownloadUrl { get; set; } = "";

    /// <summary>
    /// כתובת גיבוי, כשההורדה הישירה נכשלת.
    ///
    /// הראשית היא GitHub, כי הוא רשת הפצה חינמית. הגיבוי זורם דרך
    /// שרת SafeMe, למחשב מסונן שאינו פותר את github.com. מנסים ישיר
    /// קודם וחוסכים רוחב פס, ונופלים לשרת רק כשצריך. ריק בהצעה
    /// שאין בה גיבוי — ואז ההורדה הישירה היא היחידה.
    /// </summary>
    public string? FallbackUrl { get; set; }

    /// <summary>גיבוב הקובץ, בהקסדצימלי. נבדק אחרי ההורדה.</summary>
    public string Sha256 { get; set; } = "";

    public long SizeBytes { get; set; }

    /// <summary>
    /// המחשב שההצעה נועדה לו.
    ///
    /// בלעדיו, הצעה שנלכדה ברשת הייתה שמישה על כל מחשב אחר.
    /// </summary>
    public string HwidHash { get; set; } = "";

    public DateTimeOffset IssuedUtc { get; set; }
    public DateTimeOffset ExpiresUtc { get; set; }
}

/// <summary>
/// מה השרת קבע על הרשת הנוכחית.
///
/// השרת אינו יכול לחסום תעבורה במחשב מרוחק — הוא רק מכריע,
/// והסוכן אוכף.
/// </summary>
public sealed class NetworkVerdict
{
    /// <summary>allow · block · await_approval</summary>
    public string Action { get; set; } = "";
    public string? Reason { get; set; }
    public string? Ssid { get; set; }
    public bool IsNew { get; set; }
}

public sealed class RemoteCommand
{
    public Guid Id { get; set; }

    /// <summary>RefreshPolicy, Lockout, ReleaseLockout, RunAudit, Uninstall</summary>
    public string Type { get; set; } = "";

    public Dictionary<string, string> Args { get; set; } = new();
}

public sealed class UninstallChallengeRequest
{
    public required string Challenge { get; set; }
    public string? OperatorId { get; set; }
    public string? Reason { get; set; }
}

public sealed class UninstallChallengeResponse
{
    public string Response { get; set; } = "";
    public DateTimeOffset ExpiresUtc { get; set; }
}

/// <summary>
/// תשובת מדיניות. מכילה מעטפה חתומה ולא JSON גולמי, כדי שהסוכן יאמת
/// חתימה על הבתים שהגיעו ולא על ייצוג שהוא בנה מחדש. ראה 5.2 באפיון.
/// </summary>
public sealed class PolicyResponse
{
    public SignedEnvelope? Envelope { get; set; }
    public string? Etag { get; set; }
    public bool NotModified { get; set; }
}
