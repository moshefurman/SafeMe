using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SafeMe.Core;
using SafeMe.Core.Models;
using SafeMe.Core.Policy;
using SafeMe.Core.Security;
using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// מאמת שהמימוש ב-C# תואם לקובץ הווקטורים המשותף.
///
/// זהו הצד השני של אותו מטבע: `npm run check:vectors` מאמת את TypeScript,
/// והבדיקות כאן מאמתות את C#. שני הצדדים נכשלים על אותו קובץ, ולכן
/// אי אפשר לשנות את הפרוטוקול בצד אחד בלי שהשני ייפול.
///
/// הבדיקה הקריטית היא RsaSignatureFromTypeScript: היא מוכיחה שהסוכן
/// יאמת קוד הסרה שהשרת ייצר. זה בדיוק הכיוון שקורה בייצור.
/// </summary>
public class SharedVectorTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static readonly Lazy<TestVectorFile> Vectors = new(Load);

    /// <summary>מאתר את shared/test-vectors.json ביחס לתיקיית הפלט.</summary>
    private static TestVectorFile Load()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);

        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "shared", "test-vectors.json");
            if (File.Exists(candidate))
            {
                var json = File.ReadAllText(candidate, Encoding.UTF8);
                return JsonSerializer.Deserialize<TestVectorFile>(json, JsonOptions)
                       ?? throw new InvalidOperationException("קובץ הווקטורים ריק");
            }

            dir = dir.Parent;
        }

        throw new FileNotFoundException(
            "לא נמצא shared/test-vectors.json. יש להריץ: dotnet run --project tools/SafeMe.CodeGen -- vectors");
    }

    // ---------------------------------------------------------------- Base32

    [Fact]
    public void Base32_MatchesVectors()
    {
        foreach (var vector in Vectors.Value.Base32)
        {
            var bytes = Convert.FromHexString(vector.Hex);

            Assert.Equal(vector.Text, Base32Crockford.Encode(bytes));
            Assert.Equal(vector.Grouped, Base32Crockford.Group(Base32Crockford.Encode(bytes)));
            Assert.Equal(bytes, Base32Crockford.Decode(vector.Text)[..bytes.Length]);
        }
    }

    // ---------------------------------------------------------------- CRC16

    [Fact]
    public void Crc16_MatchesVectors()
    {
        foreach (var vector in Vectors.Value.Crc16)
        {
            Assert.Equal(vector.Crc, Crc16.Compute(Convert.FromHexString(vector.Hex)));
        }
    }

    // ---------------------------------------------------------------- אתגרים

    [Fact]
    public void Challenge_ParsesToExpectedFields()
    {
        foreach (var vector in Vectors.Value.Challenges)
        {
            Assert.True(
                UninstallChallenge.TryParse(vector.Display, out var challenge, out var error),
                $"פענוח נכשל: {error}");

            Assert.NotNull(challenge);
            Assert.Equal(vector.Flags, challenge!.Flags);
            Assert.Equal(vector.NonceHex, Convert.ToHexString(challenge.Nonce));
            Assert.Equal(vector.HwidHashHex, Convert.ToHexString(challenge.HwidHash));
            Assert.Equal(vector.Mode, challenge.Mode.ToString());
            Assert.Equal(vector.OfflineEmergency, challenge.IsOfflineEmergency);
            Assert.Equal(vector.BytesHex, Convert.ToHexString(challenge.ToBytes()));
            Assert.Equal(vector.SignedPayloadHex, Convert.ToHexString(challenge.ToSignedPayload()));
        }
    }

    [Fact]
    public void Challenge_MatchesHwidFromVector()
    {
        var vector = Vectors.Value.Challenges[0];

        Assert.True(UninstallChallenge.TryParse(vector.Display, out var challenge, out _));
        Assert.True(challenge!.MatchesHwid(vector.Hwid));
    }

    // ---------------------------------------------------------------- HMAC

    [Fact]
    public void Hmac_MatchesVectors()
    {
        foreach (var vector in Vectors.Value.Hmac)
        {
            Assert.True(UninstallChallenge.TryParse(vector.ChallengeDisplay, out var challenge, out _));

            var secret = Convert.FromHexString(vector.SecretHex);

            Assert.Equal(
                vector.Response,
                ChallengeResponseService.GenerateHmacResponse(challenge!, secret));
        }
    }

    // ---------------------------------------------------------------- RSA

    [Fact]
    public void Rsa_CSharpSignature_IsAcceptedByValidator()
    {
        var rsa = Vectors.Value.Rsa;

        Assert.True(UninstallChallenge.TryParse(rsa.ChallengeDisplay, out var challenge, out _));

        var result = ChallengeResponseService.Validate(
            rsa.ChallengeDisplay,
            rsa.SignatureFromCSharp,
            BuildOptions(challenge!, rsa.PublicKeyPem),
            challenge!.IssuedUtc);

        Assert.True(result.Granted, result.Message);
    }

    /// <summary>
    /// הבדיקה החשובה ביותר בקובץ: הסוכן ב-C# מאמת חתימה שנוצרה
    /// בשרת ב-TypeScript. זהו בדיוק מה שקורה בהסרה אמיתית.
    /// </summary>
    [Fact]
    public void Rsa_TypeScriptSignature_IsAcceptedByValidator()
    {
        var rsa = Vectors.Value.Rsa;

        Assert.False(
            string.IsNullOrWhiteSpace(rsa.SignatureFromTypeScript),
            "חסרה חתימה מ-TypeScript. יש להריץ: npm run check:vectors");

        Assert.True(UninstallChallenge.TryParse(rsa.ChallengeDisplay, out var challenge, out _));

        var result = ChallengeResponseService.Validate(
            rsa.ChallengeDisplay,
            rsa.SignatureFromTypeScript!,
            BuildOptions(challenge!, rsa.PublicKeyPem),
            challenge!.IssuedUtc);

        Assert.True(result.Granted, $"הסוכן דחה חתימה של השרת: {result.Message}");
    }

    [Fact]
    public void Rsa_SignatureForOtherChallenge_IsRejected()
    {
        var rsa = Vectors.Value.Rsa;
        var other = Vectors.Value.Challenges[1];

        Assert.True(UninstallChallenge.TryParse(other.Display, out var challenge, out _));

        var result = ChallengeResponseService.Validate(
            other.Display,
            rsa.SignatureFromCSharp,
            BuildOptions(challenge!, rsa.PublicKeyPem),
            challenge!.IssuedUtc);

        Assert.Equal(ChallengeValidation.BadResponse, result.Status);
    }

    [Fact]
    public void Rsa_ParametersMatchVector()
    {
        // אם אלה יסטו, כל החתימות ייכשלו בשקט בייצור
        Assert.Equal("PSS", Vectors.Value.Rsa.Padding);
        Assert.Equal("SHA256", Vectors.Value.Rsa.Hash);
        Assert.Equal(SHA256.HashSizeInBytes, Vectors.Value.Rsa.SaltLength);
    }

    // ---------------------------------------------------------------- מעטפת מדיניות

    /// <summary>
    /// ההוכחה לסעיף 5.2: הסוכן ב-C# מאמת מעטפת מדיניות שנחתמה בשרת
    /// ב-TypeScript, ומקבל בחזרה את התוכן המדויק — כולל עברית.
    /// זהו בדיוק הנתיב שרץ בייצור בכל משיכת מדיניות.
    /// </summary>
    [Fact]
    public void PolicyEnvelope_FromTypeScript_IsVerifiedAndDecoded()
    {
        var envelopeVector = Vectors.Value.PolicyEnvelopeFromTypeScript;

        Assert.NotNull(envelopeVector);

        var envelope = new SignedEnvelope
        {
            Alg = envelopeVector!.Alg,
            Kid = envelopeVector.Kid,
            Payload = envelopeVector.Payload,
            Signature = envelopeVector.Signature
        };

        var result = SignedEnvelopeReader.Verify<PolicyBundle>(
            envelope, Vectors.Value.Rsa.PublicKeyPem);

        Assert.True(result.Ok, $"הסוכן דחה מדיניות שהשרת חתם: {result.Message}");
        Assert.Equal(envelopeVector.ExpectedVersion, result.Value!.Version);

        // תווים עבריים הם המקום שבו הקנוניזציה הישנה הייתה נשברת
        Assert.Equal(envelopeVector.ExpectedProviderName, result.Value.Providers[0].DisplayName);
        Assert.Equal(EnforcementMode.Enforce, result.Value.Enforcement.Mode);
        Assert.Equal(RedAction.Lockout, result.Value.Enforcement.OnRedAction);
    }

    [Fact]
    public void PolicyEnvelope_TamperedByOneByte_IsRejected()
    {
        var envelopeVector = Vectors.Value.PolicyEnvelopeFromTypeScript!;

        Assert.True(SignedEnvelopeReader.TryDecodeBase64Url(envelopeVector.Payload, out var payload));

        // שינוי בית אחד בלבד בתוך התוכן החתום
        payload[^2] ^= 0x01;

        var envelope = new SignedEnvelope
        {
            Alg = envelopeVector.Alg,
            Kid = envelopeVector.Kid,
            Payload = Convert.ToBase64String(payload).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            Signature = envelopeVector.Signature
        };

        var result = SignedEnvelopeReader.Verify<PolicyBundle>(
            envelope, Vectors.Value.Rsa.PublicKeyPem);

        Assert.False(result.Ok);
    }

    // ---------------------------------------------------------------- HWID

    [Fact]
    public void Hwid_MatchesVectors()
    {
        foreach (var vector in Vectors.Value.Hwid)
        {
            Assert.Equal(vector.Id, HardwareIdBuilder.Build(vector.Components));
        }
    }

    // ---------------------------------------------------------------- עזר

    private static ChallengeValidationOptions BuildOptions(
        UninstallChallenge challenge, string publicKeyPem) => new()
    {
        Hwid = "TESTHWID0123456789ABCDEF",
        Mode = UninstallKeyMode.Rsa,
        UninstallPublicKeyPem = publicKeyPem,
        ExpectedChallenge = challenge
    };

    // ---------------------------------------------------------------- מודל

    // ---------------------------------------------------------------- יציאה

    /// <summary>
    /// רשימת הפורטים החסומים מוגדרת בשני הצדדים, ולכן היא בדיוק
    /// מה שנוטה להיפרד. הבדיקה משווה אותה ערך-ערך.
    /// </summary>
    [Fact]
    public void BaselineBlockedPorts_MatchTypeScript()
    {
        var expected = Vectors.Value.Egress!.BaselineBlockedPorts
            .Select(p => $"{p.Port}/{p.Protocol}")
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToList();

        var actual = EgressPlanner.BaselineBlockedPorts
            .Select(p => $"{p.Port}/{p.Protocol}")
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// הכלל שהשרת מייצר, מפוענח ומתוכנן בסוכן.
    ///
    /// זה הכיוון שקורה בייצור: השרת כותב את ה-JSON, הסוכן קורא
    /// אותו ובונה ממנו חוקי חומת אש. שם שדה שהשתנה בצד אחד ייפול
    /// כאן, ולא אצל לקוח.
    /// </summary>
    [Fact]
    public void EgressRuleFromTypeScript_PlansTheExpectedPosture()
    {
        var context = new EgressPlanner.Context
        {
            ServerIps = ["203.0.113.10/32"],
            AgentPaths = [@"C:\SafeMe\SafeMe.Service.exe"],
            Detection = new ProviderDetection
            {
                ProviderId = "netfree",
                DisplayName = "נטפרי",
                Trust = TrustLevel.High
            }
        };

        Assert.NotEmpty(Vectors.Value.Egress!.Cases);

        foreach (var row in Vectors.Value.Egress!.Cases)
        {
            /*
             * SafeMeJson.Options ולא JsonOptions המקומי.
             *
             * אלה ההגדרות שהסוכן משתמש בהן בפועל, וההבדל אינו
             * טכני: בלי ממיר ה-enum שבהן, "ispLevel" אינו נקרא
             * בכלל. בדיקה שמפענחת אחרת מהייצור מוכיחה רק שהיא
             * עצמה עובדת.
             */
            var rule = JsonSerializer.Deserialize<EgressRule>(
                row.Rule.GetRawText(), SafeMeJson.Options);

            Assert.NotNull(rule);

            // הוכחה שהפענוח באמת קרה ולא החזיר אובייקט ריק שנראה תקין
            if (rule!.Enabled)
            {
                Assert.Contains(80, rule.WebPorts);
                Assert.NotEmpty(rule.BlockedPorts);
                Assert.NotEmpty(rule.BlockedCidrs);
            }

            var plan = EgressPlanner.Build(rule, context);

            Assert.Equal(row.ExpectPosture, plan.Posture.ToString());
        }
    }

    public sealed class TestVectorFile
    {
        public int Version { get; set; }
        public string GeneratedBy { get; set; } = "";
        public List<Base32Row> Base32 { get; set; } = new();
        public List<CrcRow> Crc16 { get; set; } = new();
        public List<ChallengeRow> Challenges { get; set; } = new();
        public List<HmacRow> Hmac { get; set; } = new();
        public RsaRow Rsa { get; set; } = new();
        public List<HwidRow> Hwid { get; set; } = new();
        public PolicyEnvelopeRow? PolicyEnvelopeFromTypeScript { get; set; }
        public EgressVectors? Egress { get; set; }
    }

    public sealed class EgressVectors
    {
        public List<PortBlockRow> BaselineBlockedPorts { get; set; } = new();
        public List<EgressCaseRow> Cases { get; set; } = new();
    }

    public sealed class PortBlockRow
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = "";
        public string Label { get; set; } = "";
    }

    public sealed class EgressCaseRow
    {
        public string Name { get; set; } = "";
        public JsonElement Rule { get; set; }
        public string ExpectPosture { get; set; } = "";
        public string Description { get; set; } = "";
    }

    public sealed class PolicyEnvelopeRow
    {
        public string Alg { get; set; } = "";
        public string Kid { get; set; } = "";
        public string Payload { get; set; } = "";
        public string Signature { get; set; } = "";
        public int ExpectedVersion { get; set; }
        public string ExpectedProviderName { get; set; } = "";
    }

    public sealed class Base32Row
    {
        public string Hex { get; set; } = "";
        public string Text { get; set; } = "";
        public string Grouped { get; set; } = "";
    }

    public sealed class CrcRow
    {
        public string Hex { get; set; } = "";
        public ushort Crc { get; set; }
    }

    public sealed class ChallengeRow
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

    public sealed class HmacRow
    {
        public string SecretHex { get; set; } = "";
        public string ChallengeDisplay { get; set; } = "";
        public string Response { get; set; } = "";
    }

    public sealed class RsaRow
    {
        public string PublicKeyPem { get; set; } = "";
        public string PrivateKeyPem { get; set; } = "";
        public string ChallengeDisplay { get; set; } = "";
        public string SignedInputHex { get; set; } = "";
        public string SignatureFromCSharp { get; set; } = "";
        public string? SignatureFromTypeScript { get; set; }
        public string Padding { get; set; } = "";
        public string Hash { get; set; } = "";
        public int SaltLength { get; set; }
    }

    public sealed class HwidRow
    {
        public List<string?> Components { get; set; } = new();
        public string Id { get; set; } = "";
    }
}
