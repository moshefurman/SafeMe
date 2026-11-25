using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FilterPlus.Core.Security;

/// <summary>
/// מעטפה חתומה שמגיעה מהשרת.
///
/// זו הצורה היחידה שבה הסוכן מקבל מדיניות, רצפת מדיניות והיתרי הקלה.
/// העיקרון: הסוכן מאמת חתימה על **הבתים שהגיעו**, ורק אחר כך מפרסר אותם.
///
/// הגרסה הקודמת של האפיון חתמה על "JSON קנוני" שכל צד בונה מחדש. זה עבד
/// כל עוד שני הצדדים היו C#, ונשבר ברגע שהשרת נכתב ב-TypeScript:
/// System.Text.Json ו-JSON.stringify נבדלים בסדר מפתחות, בבריחת תווים
/// עבריים ובייצוג מספרים. הבדל של בית אחד פוסל את החתימה.
/// </summary>
public sealed class SignedEnvelope
{
    public const string ExpectedAlgorithm = "RSASSA-PSS-SHA256";

    /// <summary>מזהה האלגוריתם. חייב להיות ExpectedAlgorithm.</summary>
    public string Alg { get; set; } = "";

    /// <summary>מזהה המפתח שאיתו נחתם, לצורך רוטציה.</summary>
    public string Kid { get; set; } = "";

    /// <summary>הבתים המדויקים שנחתמו, בקידוד base64url.</summary>
    public string Payload { get; set; } = "";

    public string Signature { get; set; } = "";
}

public enum EnvelopeVerification
{
    Ok = 0,
    UnsupportedAlgorithm = 1,
    MalformedEncoding = 2,
    MissingKey = 3,
    BadSignature = 4,
    MalformedContent = 5
}

public sealed record EnvelopeResult<T>
{
    public EnvelopeVerification Status { get; init; }
    public T? Value { get; init; }
    public string Message { get; init; } = "";

    public bool Ok => Status == EnvelopeVerification.Ok;
}

public static class SignedEnvelopeReader
{
    /// <summary>base64url ללא ריפוד, כפי ש-Node מייצר ב-toString("base64url").</summary>
    public static bool TryDecodeBase64Url(string input, out byte[] bytes)
    {
        bytes = [];

        if (input is null) return false;

        var text = input.Replace('-', '+').Replace('_', '/');

        // השלמת ריפוד: Node משמיט אותו, ו-.NET דורש אותו
        text = (text.Length % 4) switch
        {
            2 => text + "==",
            3 => text + "=",
            0 => text,
            _ => text
        };

        try
        {
            bytes = Convert.FromBase64String(text);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// מאמת את המעטפה ומחזיר את תוכנה. הפענוח מתבצע אך ורק אחרי
    /// שהחתימה אומתה — לעולם לא לפני.
    /// </summary>
    public static EnvelopeResult<T> Verify<T>(
        SignedEnvelope envelope,
        string? publicKeyPem,
        JsonSerializerOptions? jsonOptions = null)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        if (!string.Equals(envelope.Alg, SignedEnvelope.ExpectedAlgorithm, StringComparison.Ordinal))
        {
            return new EnvelopeResult<T>
            {
                Status = EnvelopeVerification.UnsupportedAlgorithm,
                Message = $"אלגוריתם חתימה לא נתמך: {envelope.Alg}"
            };
        }

        if (string.IsNullOrWhiteSpace(publicKeyPem))
        {
            return new EnvelopeResult<T>
            {
                Status = EnvelopeVerification.MissingKey,
                Message = "לא נמצא מפתח ציבורי לאימות."
            };
        }

        if (!TryDecodeBase64Url(envelope.Payload, out var payload) ||
            !TryDecodeBase64Url(envelope.Signature, out var signature))
        {
            return new EnvelopeResult<T>
            {
                Status = EnvelopeVerification.MalformedEncoding,
                Message = "המעטפה אינה מקודדת כראוי."
            };
        }

        bool valid;

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);

            valid = rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }
        catch (CryptographicException ex)
        {
            return new EnvelopeResult<T>
            {
                Status = EnvelopeVerification.MissingKey,
                Message = $"מפתח האימות פגום: {ex.Message}"
            };
        }

        if (!valid)
        {
            return new EnvelopeResult<T>
            {
                Status = EnvelopeVerification.BadSignature,
                Message = "חתימת המעטפה אינה תקפה. התוכן שונה בדרך או נחתם במפתח אחר."
            };
        }

        try
        {
            var json = Encoding.UTF8.GetString(payload);
            var value = JsonSerializer.Deserialize<T>(json, jsonOptions ?? FilterPlusJson.Options);

            if (value is null)
            {
                return new EnvelopeResult<T>
                {
                    Status = EnvelopeVerification.MalformedContent,
                    Message = "תוכן המעטפה ריק."
                };
            }

            return new EnvelopeResult<T> { Status = EnvelopeVerification.Ok, Value = value };
        }
        catch (JsonException ex)
        {
            return new EnvelopeResult<T>
            {
                Status = EnvelopeVerification.MalformedContent,
                Message = $"תוכן המעטפה אינו JSON תקין: {ex.Message}"
            };
        }
    }
}
