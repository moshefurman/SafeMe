using System.Security.Cryptography;
using System.Text;
using SafeMe.Core.Models;

namespace SafeMe.Core.Security;

public enum ChallengeValidation
{
    Ok = 0,
    /// <summary>מחרוזת האתגר פגומה או לא ניתנת לפענוח.</summary>
    MalformedChallenge = 1,
    /// <summary>האתגר שייך למחשב אחר.</summary>
    HwidMismatch = 2,
    /// <summary>פג תוקף חלון הזמן.</summary>
    Expired = 3,
    /// <summary>האתגר נושא חותמת זמן עתידית מעבר לסבילות השעון.</summary>
    NotYetValid = 4,
    /// <summary>האתגר אינו האתגר הפתוח שהונפק על ידי השירות.</summary>
    NonceMismatch = 5,
    /// <summary>האתגר כבר נוצל בהצלחה בעבר.</summary>
    AlreadyUsed = 6,
    /// <summary>קוד התגובה אינו תואם.</summary>
    BadResponse = 7,
    /// <summary>חסימה זמנית בעקבות ניסיונות כושלים.</summary>
    RateLimited = 8,
    /// <summary>חסרה תצורת מפתח במחשב.</summary>
    MissingKeyMaterial = 9,
    /// <summary>מפתח ההסרה זהה למפתח המדיניות — ההפרדה אינה קיימת.</summary>
    KeyNotSeparate = 10
}

public sealed record ChallengeValidationResult
{
    public ChallengeValidation Status { get; init; }
    public bool Granted => Status == ChallengeValidation.Ok;

    /// <summary>הודעה בעברית להצגה ישירה למשתמש.</summary>
    public string Message { get; init; } = "";

    public int AttemptsLeft { get; init; }
    public DateTimeOffset? LockoutUntil { get; init; }

    public static ChallengeValidationResult Fail(ChallengeValidation status, string message, int attemptsLeft = 0,
        DateTimeOffset? lockoutUntil = null) =>
        new() { Status = status, Message = message, AttemptsLeft = attemptsLeft, LockoutUntil = lockoutUntil };
}

/// <summary>ההגדרות שדרושות לאימות קוד הסרה על המחשב.</summary>
public sealed class ChallengeValidationOptions
{
    /// <summary>מזהה החומרה של המחשב הנוכחי.</summary>
    public required string Hwid { get; init; }

    public UninstallKeyMode Mode { get; init; } = UninstallKeyMode.Rsa;

    /// <summary>
    /// מפתח ציבורי PEM שבו מאומת קוד ההסרה, נדרש במצב RSA.
    ///
    /// שמו מפורש ולא "מפתח השרת": זה מפתח ההסרה, והוא חייב להיות
    /// נפרד ממפתח המדיניות.
    /// </summary>
    public string? UninstallPublicKeyPem { get; init; }

    /// <summary>מפתח המדיניות, להשוואה בלבד. ראה KeySeparation.</summary>
    public string? PolicyPublicKeyPem { get; init; }

    /// <summary>סוד המחשב, נדרש במצב HMAC.</summary>
    public byte[]? DeviceSecret { get; init; }

    /// <summary>משך תוקף האתגר.</summary>
    public TimeSpan Validity { get; init; } = TimeSpan.FromMinutes(30);

    /// <summary>סבילות לסטיית שעון בין המחשב לשרת.</summary>
    public TimeSpan ClockTolerance { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>האתגר שהשירות הנפיק בפועל. אם null - לא נאכפת התאמת Nonce.</summary>
    public UninstallChallenge? ExpectedChallenge { get; init; }

    /// <summary>רשימת Nonce-ים שכבר נוצלו, למניעת שימוש חוזר.</summary>
    public IReadOnlyCollection<string>? UsedNonces { get; init; }
}

/// <summary>
/// מייצר ומאמת קודי הסרה בשיטת אתגר/תגובה.
///
/// שני מצבים:
///   RSA  - השרת חותם על האתגר; המחשב מחזיק מפתח ציבורי בלבד. מומלץ.
///   HMAC - סוד משותף שמאוחסן על המחשב. מיועד לתחנות ללא קישוריות בלבד,
///          מכיוון שחילוץ הסוד בהרשאות SYSTEM מאפשר ייצור עצמאי של קודים.
/// </summary>
public static class ChallengeResponseService
{
    /// <summary>הפרדת תחום (domain separation) - מונע שימוש חוזר בחתימה בהקשר אחר.</summary>
    private static readonly byte[] Context = "SafeMe/uninstall/v1"u8.ToArray();

    /// <summary>מספר הבתים שנלקחים מה-HMAC. 15 בתים = 120 ביט = 24 תווי Base32.</summary>
    public const int HmacResponseBytes = 15;

    // ---------------------------------------------------------------- ייצור

    /// <summary>מייצר קוד תגובה במצב HMAC. רץ בצד השרת או בכלי המוקד.</summary>
    public static string GenerateHmacResponse(UninstallChallenge challenge, byte[] deviceSecret)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(deviceSecret);

        var mac = ComputeHmac(challenge, deviceSecret);
        return Base32Crockford.Group(Base32Crockford.Encode(mac.AsSpan(0, HmacResponseBytes)));
    }

    /// <summary>מייצר קוד תגובה במצב RSA (חתימת RSA-PSS/SHA-256, מקודדת Base64).</summary>
    public static string GenerateRsaResponse(UninstallChallenge challenge, RSA privateKey)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(privateKey);

        var signature = privateKey.SignData(
            BuildSigningInput(challenge), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        return Convert.ToBase64String(signature);
    }

    // ---------------------------------------------------------------- אימות

    /// <summary>
    /// מאמת קוד תגובה מול אתגר. האימות מתבצע בשירות (SYSTEM) ולא בממשק המשתמש.
    /// הגבלת הקצב נבדקת בשכבה שמעל (UninstallAttemptGuard) לפני הקריאה לכאן.
    /// </summary>
    public static ChallengeValidationResult Validate(
        string challengeText,
        string responseText,
        ChallengeValidationOptions options,
        DateTimeOffset? nowUtc = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        var now = nowUtc ?? DateTimeOffset.UtcNow;

        // 1. פענוח האתגר ובדיקת CRC
        if (!UninstallChallenge.TryParse(challengeText, out var challenge, out var parseError) || challenge is null)
            return ChallengeValidationResult.Fail(ChallengeValidation.MalformedChallenge,
                parseError ?? "קוד האתגר אינו תקין.");

        // 2. האתגר חייב להיות של המחשב הזה
        if (!challenge.MatchesHwid(options.Hwid))
            return ChallengeValidationResult.Fail(ChallengeValidation.HwidMismatch,
                "קוד האתגר שייך למחשב אחר.");

        // 3. חלון זמן דו-כיווני
        var age = now - challenge.IssuedUtc;

        if (age > options.Validity + options.ClockTolerance)
            return ChallengeValidationResult.Fail(ChallengeValidation.Expired,
                "פג תוקף קוד האתגר. יש להפיק אתגר חדש.");

        if (age < -options.ClockTolerance)
            return ChallengeValidationResult.Fail(ChallengeValidation.NotYetValid,
                "חותמת הזמן של האתגר עתידית. בדוק את שעון המערכת.");

        // 4. התאמה לאתגר שהונפק בפועל
        if (options.ExpectedChallenge is not null && !challenge.NonceEquals(options.ExpectedChallenge))
            return ChallengeValidationResult.Fail(ChallengeValidation.NonceMismatch,
                "קוד האתגר אינו האתגר הפעיל. יש להפיק אתגר חדש.");

        // 5. מניעת שימוש חוזר
        var nonceKey = Convert.ToHexString(challenge.Nonce);

        if (options.UsedNonces is not null && options.UsedNonces.Contains(nonceKey))
            return ChallengeValidationResult.Fail(ChallengeValidation.AlreadyUsed,
                "קוד זה כבר נוצל. יש להפיק אתגר חדש.");

        // 6. חומר מפתח חייב להיות קיים לפני שמנסים לאמת
        var keyMissing = options.Mode switch
        {
            UninstallKeyMode.Hmac => options.DeviceSecret is null || options.DeviceSecret.Length == 0,
            UninstallKeyMode.Rsa => string.IsNullOrWhiteSpace(options.UninstallPublicKeyPem),
            _ => true
        };

        if (keyMissing)
            return ChallengeValidationResult.Fail(ChallengeValidation.MissingKeyMaterial,
                "לא נמצא מפתח אימות במחשב. יש לפנות לתמיכה.");

        // 6ב. ההפרדה בין מפתח ההסרה למפתח המדיניות
        //
        // הסוכן אוכף אותה בעצמו. שרת שנפרץ, או שרת מזויף שהמחשב
        // הופנה אליו, יכול לשלוח את אותו מפתח בשני השדות — ואז כל
        // יכולת לחתום מדיניות הייתה גם יכולת להסיר כל מחשב.
        if (options.Mode == UninstallKeyMode.Rsa
            && KeySeparation.Check(options.UninstallPublicKeyPem, options.PolicyPublicKeyPem)
               == KeySeparationStatus.NotSeparate)
            return ChallengeValidationResult.Fail(ChallengeValidation.KeyNotSeparate,
                "תצורת המפתחות במחשב אינה תקינה. יש לפנות לתמיכה.");


        // 7. אימות קריפטוגרפי
        var verified = options.Mode switch
        {
            UninstallKeyMode.Hmac => VerifyHmac(challenge, responseText, options.DeviceSecret),
            UninstallKeyMode.Rsa => VerifyRsa(challenge, responseText, options.UninstallPublicKeyPem),
            _ => false
        };

        if (!verified)
            return ChallengeValidationResult.Fail(ChallengeValidation.BadResponse,
                "קוד ההסרה שגוי.");

        return new ChallengeValidationResult
        {
            Status = ChallengeValidation.Ok,
            Message = "הקוד אומת בהצלחה. ההסרה מאושרת."
        };
    }

    // ---------------------------------------------------------------- פנימי

    private static byte[] BuildSigningInput(UninstallChallenge challenge)
    {
        var payload = challenge.ToSignedPayload();
        var input = new byte[Context.Length + payload.Length];

        Context.CopyTo(input, 0);
        payload.CopyTo(input, Context.Length);

        return input;
    }

    private static byte[] ComputeHmac(UninstallChallenge challenge, byte[] secret) =>
        HMACSHA256.HashData(secret, BuildSigningInput(challenge));

    private static bool VerifyHmac(UninstallChallenge challenge, string responseText, byte[]? secret)
    {
        if (secret is null) return false;
        if (!Base32Crockford.TryDecode(Base32Crockford.Normalize(responseText), out var supplied)) return false;
        if (supplied.Length < HmacResponseBytes) return false;

        var expected = ComputeHmac(challenge, secret).AsSpan(0, HmacResponseBytes);

        // השוואה בזמן קבוע מונעת התקפת תזמון על ניחוש בית-אחר-בית
        return CryptographicOperations.FixedTimeEquals(supplied.AsSpan(0, HmacResponseBytes), expected);
    }

    private static bool VerifyRsa(UninstallChallenge challenge, string responseText, string? publicKeyPem)
    {
        if (string.IsNullOrWhiteSpace(publicKeyPem)) return false;

        byte[] signature;

        try
        {
            signature = Convert.FromBase64String(responseText.Trim()
                .Replace("\r", "").Replace("\n", "").Replace(" ", ""));
        }
        catch (FormatException)
        {
            return false;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);

            return rsa.VerifyData(
                BuildSigningInput(challenge), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>מייצר אסימון הסרה חד-פעמי שנמסר למתקין לאחר אימות מוצלח.</summary>
    public static string CreateUninstallToken(string hwid, UninstallChallenge challenge)
    {
        var material = Encoding.UTF8.GetBytes(hwid)
            .Concat(challenge.Nonce)
            .Concat(BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
            .ToArray();

        return Base32Crockford.Encode(SHA256.HashData(material).AsSpan(0, 20));
    }
}
