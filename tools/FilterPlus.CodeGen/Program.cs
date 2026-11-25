using System.Security.Cryptography;
using FilterPlus.Core.Models;
using FilterPlus.Core.Security;

namespace FilterPlus.CodeGen;

/// <summary>
/// כלי צד שרת ומוקד: מפענח אתגר, מייצר קוד הסרה, ומנפיק זוג מפתחות.
///
/// בפריסה אמיתית הפעולות האלה מתבצעות בשרת מאחורי אימות נציג ותיעוד מלא.
/// הכלי הזה קיים לפיתוח, לבדיקות ולגיבוי אופליין.
/// </summary>
public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "keygen" => KeyGen(args),
                "inspect" => Inspect(args),
                "respond" => Respond(args),
                "demo" => Demo(),
                "vectors" => VectorGenerator.Generate(
                    GetArg(args, "--out") ?? "shared/test-vectors.json"),
                _ => Unknown(args[0])
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"שגיאה: {ex.Message}");
            return 2;
        }
    }

    // ------------------------------------------------------------ פקודות

    /// <summary>מנפיק זוג מפתחות RSA-2048 לשימוש בחתימת קודי הסרה ומדיניות.</summary>
    private static int KeyGen(string[] args)
    {
        var prefix = GetArg(args, "--out") ?? "filterplus-server";

        using var rsa = RSA.Create(2048);

        var privatePath = prefix + "-private.pem";
        var publicPath = prefix + "-public.pem";

        File.WriteAllText(privatePath, rsa.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(publicPath, rsa.ExportSubjectPublicKeyInfoPem());

        Console.WriteLine($"מפתח פרטי נכתב ל: {privatePath}");
        Console.WriteLine($"מפתח ציבורי נכתב ל: {publicPath}");
        Console.WriteLine();
        Console.WriteLine("המפתח הפרטי נשאר בשרת בלבד. המפתח הציבורי נשלח למכשירים בעת הרישום.");

        return 0;
    }

    /// <summary>מפענח אתגר ומציג את תוכנו, לצורך אימות ידני במוקד.</summary>
    private static int Inspect(string[] args)
    {
        var challengeText = GetArg(args, "--challenge") ?? throw new ArgumentException("חסר --challenge");

        if (!UninstallChallenge.TryParse(challengeText, out var challenge, out var error) || challenge is null)
        {
            Console.Error.WriteLine($"אתגר לא תקין: {error}");
            return 3;
        }

        var age = DateTimeOffset.UtcNow - challenge.IssuedUtc;

        Console.WriteLine($"גרסה           : {challenge.Version}");
        Console.WriteLine($"מצב אימות      : {challenge.Mode}");
        Console.WriteLine($"חירום אופליין  : {(challenge.IsOfflineEmergency ? "כן" : "לא")}");
        Console.WriteLine($"תמצית HWID     : {Convert.ToHexString(challenge.HwidHash)}");
        Console.WriteLine($"הונפק (UTC)    : {challenge.IssuedUtc:yyyy-MM-dd HH:mm}");
        Console.WriteLine($"גיל            : {age.TotalMinutes:F0} דקות");
        Console.WriteLine($"Nonce          : {Convert.ToHexString(challenge.Nonce)}");
        Console.WriteLine($"בתוקף          : {(age.TotalMinutes is >= -5 and <= 35 ? "כן" : "לא")}");

        return 0;
    }

    /// <summary>מייצר קוד הסרה עבור אתגר נתון.</summary>
    private static int Respond(string[] args)
    {
        var challengeText = GetArg(args, "--challenge") ?? throw new ArgumentException("חסר --challenge");

        if (!UninstallChallenge.TryParse(challengeText, out var challenge, out var error) || challenge is null)
        {
            Console.Error.WriteLine($"אתגר לא תקין: {error}");
            return 3;
        }

        var age = DateTimeOffset.UtcNow - challenge.IssuedUtc;

        if (age > TimeSpan.FromMinutes(35))
            Console.Error.WriteLine("אזהרה: האתגר ישן מ-35 דקות וסביר שכבר פג תוקפו.");

        var keyPath = GetArg(args, "--key");
        var secret = GetArg(args, "--secret");

        string response;

        if (keyPath is not null)
        {
            if (challenge.Mode != UninstallKeyMode.Rsa)
                Console.Error.WriteLine("אזהרה: האתגר מסומן כ-HMAC אך נעשה שימוש במפתח RSA.");

            using var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(keyPath));

            response = ChallengeResponseService.GenerateRsaResponse(challenge, rsa);
        }
        else if (secret is not null)
        {
            if (challenge.Mode != UninstallKeyMode.Hmac)
                Console.Error.WriteLine("אזהרה: האתגר מסומן כ-RSA אך נעשה שימוש בסוד HMAC.");

            response = ChallengeResponseService.GenerateHmacResponse(challenge, Convert.FromBase64String(secret));
        }
        else
        {
            throw new ArgumentException("נדרש --key (RSA) או --secret (HMAC)");
        }

        Console.WriteLine();
        Console.WriteLine("קוד ההסרה:");
        Console.WriteLine(response);
        Console.WriteLine();
        Console.WriteLine($"תקף עד: {challenge.IssuedUtc.AddMinutes(30).ToLocalTime():HH:mm}");

        return 0;
    }

    /// <summary>
    /// מדגים את המחזור המלא בלי צורך בהתקנה: המכשיר מפיק אתגר, השרת חותם,
    /// והמכשיר מאמת. משמש לבדיקת שפיות אחרי שינויים בפרוטוקול.
    /// </summary>
    private static int Demo()
    {
        const string hwid = "DEMOHWID0123456789ABCDEFGH";

        using var serverKey = RSA.Create(2048);
        var publicPem = serverKey.ExportSubjectPublicKeyInfoPem();

        Console.WriteLine("=== הדגמת מחזור אתגר ותגובה ===");
        Console.WriteLine();

        // צד המכשיר
        var challenge = UninstallChallenge.Create(hwid, UninstallKeyMode.Rsa);
        var challengeText = challenge.ToDisplayString();

        Console.WriteLine($"1. המכשיר מפיק אתגר ({challengeText.Length} תווים):");
        Console.WriteLine($"   {challengeText}");
        Console.WriteLine();

        // צד השרת
        var response = ChallengeResponseService.GenerateRsaResponse(challenge, serverKey);

        Console.WriteLine("2. השרת חותם ומחזיר קוד הסרה:");
        Console.WriteLine($"   {response[..48]}... ({response.Length} תווים)");
        Console.WriteLine();

        // אימות במכשיר
        var options = new ChallengeValidationOptions
        {
            Hwid = hwid,
            Mode = UninstallKeyMode.Rsa,
            UninstallPublicKeyPem = publicPem,
            ExpectedChallenge = challenge
        };

        var valid = ChallengeResponseService.Validate(challengeText, response, options);
        Console.WriteLine($"3. אימות קוד תקין : {(valid.Granted ? "אושר" : "נדחה")} — {valid.Message}");

        // ניסיון עם מפתח זר
        using var attackerKey = RSA.Create(2048);
        var forged = ChallengeResponseService.GenerateRsaResponse(challenge, attackerKey);
        var forgedResult = ChallengeResponseService.Validate(challengeText, forged, options);

        Console.WriteLine($"4. אימות קוד מזויף: {(forgedResult.Granted ? "אושר" : "נדחה")} — {forgedResult.Message}");

        // ניסיון לאחר פקיעת תוקף
        var expired = ChallengeResponseService.Validate(
            challengeText, response, options, DateTimeOffset.UtcNow.AddHours(2));

        Console.WriteLine($"5. אימות לאחר שעתיים: {(expired.Granted ? "אושר" : "נדחה")} — {expired.Message}");

        Console.WriteLine();

        return valid.Granted && !forgedResult.Granted && !expired.Granted ? 0 : 4;
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine($"פקודה לא מוכרת: {command}");
        PrintUsage();

        return 1;
    }

    // ------------------------------------------------------------ עזר

    private static string? GetArg(string[] args, string name)
    {
        var index = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));

        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("FilterPlus.CodeGen — כלי הנפקת קודי הסרה");
        Console.WriteLine();
        Console.WriteLine("  keygen  [--out <prefix>]");
        Console.WriteLine("      מנפיק זוג מפתחות RSA-2048.");
        Console.WriteLine();
        Console.WriteLine("  inspect --challenge <code>");
        Console.WriteLine("      מפענח אתגר ומציג את פרטיו.");
        Console.WriteLine();
        Console.WriteLine("  respond --challenge <code> --key <private.pem>");
        Console.WriteLine("  respond --challenge <code> --secret <base64>");
        Console.WriteLine("      מייצר קוד הסרה במצב RSA או HMAC.");
        Console.WriteLine();
        Console.WriteLine("  vectors [--out shared/test-vectors.json]");
        Console.WriteLine("      מייצר וקטורי בדיקה משותפים לצד ה-TypeScript.");
    }
}
