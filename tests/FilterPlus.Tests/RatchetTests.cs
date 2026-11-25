using System.Security.Cryptography;
using System.Text;
using FilterPlus.Core;
using FilterPlus.Core.Models;
using FilterPlus.Core.Policy;
using FilterPlus.Core.Security;
using Xunit;

namespace FilterPlus.Tests;

/// <summary>
/// בדיקות מנגנון המחגר: שינוי מרחוק יכול רק להדק, לעולם לא לשחרר.
///
/// כל בדיקה כאן מייצגת דרך שבה תוקף — או שרת פרוץ — היה מנסה להקל
/// על מחשב בשטח.
/// </summary>
public class StrictnessComparerTests
{
    private static PolicyBundle BuildPolicy(
        EnforcementMode mode = EnforcementMode.Enforce,
        RedAction onRed = RedAction.Lockout,
        int green = 85,
        int yellow = 60,
        string[]? providers = null,
        (string Id, int Weight)[]? probes = null)
    {
        var policy = PolicyBundle.CreateDefault();

        policy.Enforcement = new EnforcementPolicy
        {
            Mode = mode,
            OnRedAction = onRed,
            MinScoreForGreen = green,
            MinScoreForYellow = yellow,
            AllowedNetworks = new AllowedNetworks
            {
                RequireProvider = (providers ?? ["netfree"]).ToList()
            }
        };

        foreach (var (id, weight) in probes ?? [("adult-01", 30)])
        {
            policy.ContentProbes.Add(new ContentProbeRule
            {
                Id = id,
                Url = $"https://probe.filterplus.co.il/c/{id}",
                Weight = weight
            });
        }

        return policy;
    }

    private static PolicyStrictness Of(PolicyBundle policy) => PolicyStrictness.FromPolicy(policy);

    [Fact]
    public void IdenticalPolicy_IsNotLoosening()
    {
        var delta = StrictnessComparer.Compare(Of(BuildPolicy()), Of(BuildPolicy()));

        Assert.False(delta.IsLoosening);
    }

    [Fact]
    public void LoweringMode_IsLoosening()
    {
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(mode: EnforcementMode.Enforce)),
            Of(BuildPolicy(mode: EnforcementMode.Monitor)));

        Assert.True(delta.IsLoosening);
        Assert.Contains(delta.Reasons, r => r.Contains("מצב האכיפה"));
    }

    [Fact]
    public void RaisingMode_IsAllowed()
    {
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(mode: EnforcementMode.Warn)),
            Of(BuildPolicy(mode: EnforcementMode.Enforce)));

        Assert.False(delta.IsLoosening);
    }

    [Fact]
    public void LoweringRedAction_IsLoosening()
    {
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(onRed: RedAction.Lockout)),
            Of(BuildPolicy(onRed: RedAction.Warn)));

        Assert.True(delta.IsLoosening);
    }

    [Fact]
    public void LoweringScoreThreshold_IsLoosening()
    {
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(green: 85)),
            Of(BuildPolicy(green: 50)));

        Assert.True(delta.IsLoosening);
        Assert.Contains(delta.Reasons, r => r.Contains("סף הציון הירוק"));
    }

    [Fact]
    public void AddingApprovedProvider_IsLoosening()
    {
        // הוספת ספק מאושר מרחיבה את מה שמותר, ולכן היא הקלה
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(providers: ["netfree"])),
            Of(BuildPolicy(providers: ["netfree", "some-open-isp"])));

        Assert.True(delta.IsLoosening);
        Assert.Contains(delta.Reasons, r => r.Contains("ספקים מאושרים"));
    }

    [Fact]
    public void RemovingProviderRequirementEntirely_IsLoosening()
    {
        // רשימה ריקה משמעה "כל ספק מותר", וזה המצב המקל ביותר.
        // תת-קבוצה ריקה נראית מחמירה מבחינה מתמטית, ולכן זו מלכודת אמיתית.
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(providers: ["netfree", "rimon"])),
            Of(BuildPolicy(providers: [])));

        Assert.True(delta.IsLoosening);
        Assert.Contains(delta.Reasons, r => r.Contains("בוטלה"));
    }

    [Fact]
    public void NarrowingProviderList_IsAllowed()
    {
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(providers: ["netfree", "rimon"])),
            Of(BuildPolicy(providers: ["netfree"])));

        Assert.False(delta.IsLoosening);
    }

    [Fact]
    public void RemovingProbe_IsLoosening()
    {
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(probes: [("adult-01", 30), ("gambling-01", 15)])),
            Of(BuildPolicy(probes: [("adult-01", 30)])));

        Assert.True(delta.IsLoosening);
        Assert.Contains(delta.Reasons, r => r.Contains("gambling-01"));
    }

    [Fact]
    public void LoweringProbeWeight_IsLoosening()
    {
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(probes: [("adult-01", 30)])),
            Of(BuildPolicy(probes: [("adult-01", 5)])));

        Assert.True(delta.IsLoosening);
    }

    [Fact]
    public void AddingProbe_IsAllowed()
    {
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(probes: [("adult-01", 30)])),
            Of(BuildPolicy(probes: [("adult-01", 30), ("ai-claude", 15)])));

        Assert.False(delta.IsLoosening);
    }

    [Fact]
    public void TighteningOneAxisDoesNotOffsetLooseningAnother()
    {
        // התרחיש שהכלל נועד למנוע: מעלים סף זניח ומורידים את מצב האכיפה
        var delta = StrictnessComparer.Compare(
            Of(BuildPolicy(mode: EnforcementMode.Enforce, green: 85)),
            Of(BuildPolicy(mode: EnforcementMode.Monitor, green: 99)));

        Assert.True(delta.IsLoosening);
        Assert.Contains(delta.Reasons, r => r.Contains("מצב האכיפה"));
    }
}

public class LooseningGrantTests
{
    private const string Hwid = "TESTHWID0123456789ABCDEF";

    private static PolicyFloorSpec StrictFloor => new()
    {
        Mode = EnforcementMode.Enforce,
        OnRedAction = RedAction.Lockout,
        MinScoreForGreen = 85,
        MinScoreForYellow = 60,
        RequireProvider = ["netfree"]
    };

    private static LooseningGrant BuildGrant(
        string hwid = Hwid,
        PolicyFloorSpec? from = null,
        PolicyFloorSpec? to = null,
        int expiresInMinutes = 30) => new()
    {
        HwidHash = Convert.ToHexString(UninstallChallenge.ComputeHwidHash(hwid)),
        Nonce = "AABBCCDD",
        IssuedUtc = DateTimeOffset.UtcNow,
        ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(expiresInMinutes),
        FromFloor = from ?? StrictFloor,
        ToFloor = to ?? new PolicyFloorSpec
        {
            Mode = EnforcementMode.Warn,
            OnRedAction = RedAction.Warn,
            MinScoreForGreen = 60,
            MinScoreForYellow = 40,
            RequireProvider = ["netfree"]
        },
        ApprovedBy = "op-17",
        Reason = "החלפת מחשב"
    };

    [Fact]
    public void ValidGrant_IsAccepted()
    {
        var result = LooseningGrantValidator.Validate(BuildGrant(), Hwid, StrictFloor, []);

        Assert.True(result.Ok, result.Message);
    }

    [Fact]
    public void GrantForAnotherMachine_IsRejected()
    {
        var grant = BuildGrant(hwid: "OTHERMACHINE0123456789AB");
        var result = LooseningGrantValidator.Validate(grant, Hwid, StrictFloor, []);

        Assert.Equal(GrantValidation.HwidMismatch, result.Status);
    }

    [Fact]
    public void ExpiredGrant_IsRejected()
    {
        var grant = BuildGrant(expiresInMinutes: -60);
        var result = LooseningGrantValidator.Validate(grant, Hwid, StrictFloor, []);

        Assert.Equal(GrantValidation.Expired, result.Status);
    }

    [Fact]
    public void ReusedNonce_IsRejected()
    {
        var grant = BuildGrant();
        var result = LooseningGrantValidator.Validate(grant, Hwid, StrictFloor, [grant.Nonce]);

        Assert.Equal(GrantValidation.AlreadyUsed, result.Status);
    }

    [Fact]
    public void GrantFromDifferentFloor_IsRejected()
    {
        // היתר ישן שנשמר, אחרי שהרצפה בינתיים הועלתה
        var oldFloor = new PolicyFloorSpec
        {
            Mode = EnforcementMode.Warn,
            OnRedAction = RedAction.Warn,
            MinScoreForGreen = 60,
            MinScoreForYellow = 40,
            RequireProvider = ["netfree"]
        };

        var grant = BuildGrant(from: oldFloor);
        var result = LooseningGrantValidator.Validate(grant, Hwid, StrictFloor, []);

        Assert.Equal(GrantValidation.FloorMismatch, result.Status);
    }

    [Fact]
    public void GrantThatTightens_IsRejectedAsSuspicious()
    {
        var tighter = new PolicyFloorSpec
        {
            Mode = EnforcementMode.Enforce,
            OnRedAction = RedAction.Lockout,
            MinScoreForGreen = 95,
            MinScoreForYellow = 80,
            RequireProvider = ["netfree"]
        };

        var result = LooseningGrantValidator.Validate(
            BuildGrant(to: tighter), Hwid, StrictFloor, []);

        Assert.Equal(GrantValidation.NotALoosening, result.Status);
    }
}

public class SignedEnvelopeTests
{
    private static (SignedEnvelope Envelope, string PublicPem) Sign(object value)
    {
        using var rsa = RSA.Create(2048);

        var bytes = Encoding.UTF8.GetBytes(FilterPlusJson.Serialize(value));
        var signature = rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        return (new SignedEnvelope
        {
            Alg = SignedEnvelope.ExpectedAlgorithm,
            Kid = "test-1",
            Payload = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            Signature = Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        }, rsa.ExportSubjectPublicKeyInfoPem());
    }

    [Fact]
    public void ValidEnvelope_IsVerifiedAndDecoded()
    {
        var (envelope, pem) = Sign(new PolicyFloorSpec { MinScoreForGreen = 90 });

        var result = SignedEnvelopeReader.Verify<PolicyFloorSpec>(envelope, pem);

        Assert.True(result.Ok, result.Message);
        Assert.Equal(90, result.Value!.MinScoreForGreen);
    }

    [Fact]
    public void TamperedPayload_IsRejected()
    {
        var (envelope, pem) = Sign(new PolicyFloorSpec { Mode = EnforcementMode.Enforce });

        // התוקף מחליף את התוכן ומשאיר את החתימה
        var forged = Encoding.UTF8.GetBytes(
            FilterPlusJson.Serialize(new PolicyFloorSpec { Mode = EnforcementMode.Monitor }));

        envelope.Payload = Convert.ToBase64String(forged)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var result = SignedEnvelopeReader.Verify<PolicyFloorSpec>(envelope, pem);

        Assert.Equal(EnvelopeVerification.BadSignature, result.Status);
    }

    [Fact]
    public void WrongAlgorithm_IsRejected()
    {
        var (envelope, pem) = Sign(new PolicyFloorSpec());
        envelope.Alg = "HS256";

        Assert.Equal(
            EnvelopeVerification.UnsupportedAlgorithm,
            SignedEnvelopeReader.Verify<PolicyFloorSpec>(envelope, pem).Status);
    }

    [Fact]
    public void MissingPublicKey_IsRejected()
    {
        var (envelope, _) = Sign(new PolicyFloorSpec());

        Assert.Equal(
            EnvelopeVerification.MissingKey,
            SignedEnvelopeReader.Verify<PolicyFloorSpec>(envelope, null).Status);
    }

    [Fact]
    public void Base64Url_WithoutPadding_IsDecoded()
    {
        // Node משמיט את הריפוד, .NET דורש אותו. זו מלכודת קלאסית.
        foreach (var length in Enumerable.Range(1, 8))
        {
            var data = RandomNumberGenerator.GetBytes(length);
            var encoded = Convert.ToBase64String(data)
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

            Assert.True(SignedEnvelopeReader.TryDecodeBase64Url(encoded, out var decoded));
            Assert.Equal(data, decoded);
        }
    }
}
