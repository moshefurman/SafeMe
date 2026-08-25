using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SafeMe.Core.Models;
using SafeMe.Core.Security;

namespace SafeMe.CodeGen;

/// <summary>
/// מייצר וקטורי בדיקה משותפים לשני המימושים.
///
/// הבעיה שזה פותר: קוד ההסרה מיוצר בשרת ב-TypeScript ומאומת בסוכן ב-C#.
/// שני מימושים נפרדים של אותו פרוטוקול נוטים להיפרד בשקט — סדר בתים,
/// ריפוד Base32, אורך ה-salt ב-PSS. הקובץ הזה הופך כל סטייה כזו לכשל CI
/// בשני הצדדים, במקום לתקלה שמתגלה כשלקוח לא מצליח להסיר.
///
/// כל הערכים כאן דטרמיניסטיים במכוון: אין קריאה ל-Create() ואין אקראיות,
/// כדי שהרצה חוזרת תפיק בדיוק את אותו קובץ.
/// </summary>
public static class VectorGenerator
{
    private const int PayloadLength = UninstallChallenge.PayloadLength;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        // camelCase כדי שהצד ב-TypeScript יקרא את אותם שמות בדיוק
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>UTF-8 ללא BOM. JSON.parse ב-Node נכשל על BOM.</summary>
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    public static int Generate(string outputPath)
    {
        var vectors = new TestVectors
        {
            Version = 1,
            GeneratedBy = "SafeMe.CodeGen (C#)",
            Context = "SafeMe/uninstall/v1",
            Base32 = BuildBase32Vectors(),
            Crc16 = BuildCrcVectors(),
            Challenges = BuildChallengeVectors(),
            Hmac = BuildHmacVectors(),
            Rsa = BuildRsaVector(),
            Hwid = BuildHwidVectors()
        };

        var directory = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

        File.WriteAllText(outputPath, JsonSerializer.Serialize(vectors, JsonOptions), Utf8NoBom);

        Console.WriteLine($"נכתבו וקטורי בדיקה אל: {outputPath}");
        Console.WriteLine($"  Base32     : {vectors.Base32.Count}");
        Console.WriteLine($"  CRC16      : {vectors.Crc16.Count}");
        Console.WriteLine($"  אתגרים     : {vectors.Challenges.Count}");
        Console.WriteLine($"  HMAC       : {vectors.Hmac.Count}");
        Console.WriteLine($"  HWID       : {vectors.Hwid.Count}");
        Console.WriteLine();
        Console.WriteLine("הצד ב-TypeScript חייב לעבור את כולם: npm run check:vectors");

        return 0;
    }

    // ---------------------------------------------------------------- Base32

    private static List<Base32Vector> BuildBase32Vectors()
    {
        string[] samples =
        [
            "",
            "00",
            "FF",
            "0011223344556677",
            "000102030405060708090A0B0C0D0E0F",
            // כל 32 ערכי ה-Base32 בדיוק פעם אחת, כדי לכסות את כל טבלת התווים
            "00443214C74254B635CF84653A56D7C675BE77DF"
        ];

        return samples.Select(hex =>
        {
            var bytes = Convert.FromHexString(hex);

            return new Base32Vector
            {
                Hex = hex,
                Text = Base32Crockford.Encode(bytes),
                Grouped = Base32Crockford.Group(Base32Crockford.Encode(bytes))
            };
        }).ToList();
    }

    // ---------------------------------------------------------------- CRC16

    private static List<CrcVector> BuildCrcVectors()
    {
        string[] samples =
        [
            "",
            "00",
            "313233343536373839",   // "123456789" - וקטור הייחוס המקובל
            "0011223344556677889900112233445566778899"
        ];

        return samples.Select(hex => new CrcVector
        {
            Hex = hex,
            Crc = Crc16.Compute(Convert.FromHexString(hex))
        }).ToList();
    }

    // ---------------------------------------------------------------- אתגרים

    /// <summary>
    /// בונה אתגר מערכים קבועים, בלי אקראיות, כדי שהווקטור יהיה יציב.
    /// המבנה חייב להתאים בדיוק ל-UninstallChallenge.ToBytes.
    /// </summary>
    private static byte[] BuildChallengeBytes(
        byte version, byte flags, byte[] hwidHash, uint issuedMinutes, byte[] nonce)
    {
        var bytes = new byte[UninstallChallenge.TotalLength];

        bytes[0] = version;
        bytes[1] = flags;
        hwidHash.AsSpan(0, 8).CopyTo(bytes.AsSpan(2, 8));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(10, 4), issuedMinutes);
        nonce.AsSpan(0, 6).CopyTo(bytes.AsSpan(14, 6));

        var crc = Crc16.Compute(bytes.AsSpan(0, PayloadLength));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(20, 2), crc);

        return bytes;
    }

    private static readonly (string Hwid, byte Flags, uint Minutes, string NonceHex)[] ChallengeInputs =
    [
        ("TESTHWID0123456789ABCDEF", UninstallChallenge.FlagRsa, 29_000_000, "0102030405 06".Replace(" ", "")),
        ("TESTHWID0123456789ABCDEF", 0,                          29_000_001, "FFFFFFFFFFFF"),
        ("OTHERMACHINE0123456789AB", UninstallChallenge.FlagRsa | UninstallChallenge.FlagOfflineEmergency,
                                                                 29_123_456, "A1B2C3D4E5F6")
    ];

    private static List<ChallengeVector> BuildChallengeVectors()
    {
        var results = new List<ChallengeVector>();

        foreach (var (hwid, flags, minutes, nonceHex) in ChallengeInputs)
        {
            var hwidHash = UninstallChallenge.ComputeHwidHash(hwid);
            var nonce = Convert.FromHexString(nonceHex);
            var bytes = BuildChallengeBytes(UninstallChallenge.CurrentVersion, flags, hwidHash, minutes, nonce);
            var display = Base32Crockford.Group(Base32Crockford.Encode(bytes));

            // אימות עצמי: הקידוד חייב להיות הפיך גם בצד שיצר אותו
            if (!UninstallChallenge.TryParse(display, out var parsed, out var error) || parsed is null)
                throw new InvalidOperationException($"אתגר שנוצר אינו ניתן לפענוח: {error}");

            results.Add(new ChallengeVector
            {
                Hwid = hwid,
                HwidHashHex = Convert.ToHexString(hwidHash),
                Flags = flags,
                IssuedUnixMinutes = minutes,
                NonceHex = nonceHex,
                BytesHex = Convert.ToHexString(bytes),
                SignedPayloadHex = Convert.ToHexString(bytes.AsSpan(0, PayloadLength)),
                Display = display,
                Mode = parsed.Mode.ToString(),
                OfflineEmergency = parsed.IsOfflineEmergency
            });
        }

        return results;
    }

    // ---------------------------------------------------------------- HMAC

    private static List<HmacVector> BuildHmacVectors()
    {
        // סוד קבוע לבדיקות בלבד. אינו בשימוש בשום סביבה אמיתית.
        var secret = Convert.FromHexString(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        var results = new List<HmacVector>();

        foreach (var vector in BuildChallengeVectors())
        {
            if (!UninstallChallenge.TryParse(vector.Display, out var challenge, out _) || challenge is null)
                continue;

            results.Add(new HmacVector
            {
                SecretHex = Convert.ToHexString(secret),
                ChallengeDisplay = vector.Display,
                Response = ChallengeResponseService.GenerateHmacResponse(challenge, secret)
            });
        }

        return results;
    }

    // ---------------------------------------------------------------- RSA

    /// <summary>
    /// מפתח בדיקה קבוע. RSA-PSS אינו דטרמיניסטי, ולכן החתימה נוצרת פעם אחת
    /// ונשמרת. הצד ב-TypeScript מאמת אותה, וכותב בחזרה חתימה משלו שהצד
    /// ב-C# מאמת. כך שני הכיוונים מכוסים.
    /// </summary>
    private static RsaVector BuildRsaVector()
    {
        var challenge = BuildChallengeVectors()[0];

        if (!UninstallChallenge.TryParse(challenge.Display, out var parsed, out _) || parsed is null)
            throw new InvalidOperationException("אתגר הבדיקה אינו תקין");

        using var rsa = RSA.Create(2048);

        var context = Encoding.UTF8.GetBytes("SafeMe/uninstall/v1");
        var payload = parsed.ToSignedPayload();
        var signedInput = context.Concat(payload).ToArray();

        return new RsaVector
        {
            PublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
            PrivateKeyPem = rsa.ExportPkcs8PrivateKeyPem(),
            ChallengeDisplay = challenge.Display,
            SignedInputHex = Convert.ToHexString(signedInput),
            SignatureFromCSharp = ChallengeResponseService.GenerateRsaResponse(parsed, rsa),
            Padding = "PSS",
            Hash = "SHA256",
            SaltLength = 32
        };
    }

    // ---------------------------------------------------------------- HWID

    private static List<HwidVector> BuildHwidVectors()
    {
        List<string?[]> inputs =
        [
            ["GUID-1234-5678", "BASEBOARD-9999", "CPU-ABCDEF"],
            ["GUID-1234-5678", "To be filled by O.E.M.", null, "  ", "BASEBOARD-9999"],
            ["guid-1234-5678", "baseboard-9999", "cpu-abcdef"]
        ];

        return inputs.Select(components => new HwidVector
        {
            Components = components.ToList(),
            Id = HardwareIdBuilder.Build(components)
        }).ToList();
    }
}

// ---------------------------------------------------------------- מודל הקובץ

public sealed class TestVectors
{
    public int Version { get; set; }
    public string GeneratedBy { get; set; } = "";
    public string Context { get; set; } = "";
    public List<Base32Vector> Base32 { get; set; } = new();
    public List<CrcVector> Crc16 { get; set; } = new();
    public List<ChallengeVector> Challenges { get; set; } = new();
    public List<HmacVector> Hmac { get; set; } = new();
    public RsaVector Rsa { get; set; } = new();
    public List<HwidVector> Hwid { get; set; } = new();
}

public sealed class Base32Vector
{
    public string Hex { get; set; } = "";
    public string Text { get; set; } = "";
    public string Grouped { get; set; } = "";
}

public sealed class CrcVector
{
    public string Hex { get; set; } = "";
    public ushort Crc { get; set; }
}

public sealed class ChallengeVector
{
    public string Hwid { get; set; } = "";
    public string HwidHashHex { get; set; } = "";
    public byte Flags { get; set; }
    public uint IssuedUnixMinutes { get; set; }
    public string NonceHex { get; set; } = "";
    public string BytesHex { get; set; } = "";
    public string SignedPayloadHex { get; set; } = "";
    public string Display { get; set; } = "";
    public string Mode { get; set; } = "";
    public bool OfflineEmergency { get; set; }
}

public sealed class HmacVector
{
    public string SecretHex { get; set; } = "";
    public string ChallengeDisplay { get; set; } = "";
    public string Response { get; set; } = "";
}

public sealed class RsaVector
{
    public string PublicKeyPem { get; set; } = "";
    public string PrivateKeyPem { get; set; } = "";
    public string ChallengeDisplay { get; set; } = "";
    public string SignedInputHex { get; set; } = "";
    public string SignatureFromCSharp { get; set; } = "";

    /// <summary>מאוכלס על ידי הצד ב-TypeScript, ומאומת בחזרה ב-C#.</summary>
    public string? SignatureFromTypeScript { get; set; }

    public string Padding { get; set; } = "PSS";
    public string Hash { get; set; } = "SHA256";
    public int SaltLength { get; set; } = 32;
}

public sealed class HwidVector
{
    public List<string?> Components { get; set; } = new();
    public string Id { get; set; } = "";
}
