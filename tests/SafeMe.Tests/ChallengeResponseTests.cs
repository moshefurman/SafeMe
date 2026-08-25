using System.Security.Cryptography;
using SafeMe.Core.Models;
using SafeMe.Core.Security;
using Xunit;

namespace SafeMe.Tests;

public class Base32Tests
{
    [Fact]
    public void RoundTrip_PreservesBytes()
    {
        var data = new byte[] { 0x00, 0x1F, 0xA3, 0xFF, 0x42, 0x7C, 0x91 };

        var encoded = Base32Crockford.Encode(data);
        var decoded = Base32Crockford.Decode(encoded);

        Assert.Equal(data, decoded[..data.Length]);
    }

    [Fact]
    public void Decode_IgnoresHyphensAndCase()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var encoded = Base32Crockford.Group(Base32Crockford.Encode(data));

        Assert.Equal(data, Base32Crockford.Decode(encoded.ToLowerInvariant())[..5]);
    }

    [Theory]
    [InlineData('I', '1')]
    [InlineData('L', '1')]
    [InlineData('O', '0')]
    public void Decode_MapsConfusableCharacters(char confusable, char canonical)
    {
        // מוקדן שמקריא קוד בטלפון עלול להחליף בין התווים האלה
        var confusableInput = new string([confusable, '2', '3', '4', '5', '6', '7', '8']);
        var canonicalInput = new string([canonical, '2', '3', '4', '5', '6', '7', '8']);

        Assert.Equal(Base32Crockford.Decode(canonicalInput), Base32Crockford.Decode(confusableInput));
    }

    [Fact]
    public void Decode_RejectsInvalidCharacter()
    {
        Assert.Throws<FormatException>(() => Base32Crockford.Decode("ABC$DEF"));
    }
}

public class UninstallChallengeTests
{
    private const string Hwid = "TESTHWID0123456789ABCDEF";

    [Fact]
    public void Create_RoundTripsThroughDisplayString()
    {
        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Rsa);
        var text = challenge.ToDisplayString();

        Assert.True(UninstallChallenge.TryParse(text, out var parsed, out var error), error);
        Assert.NotNull(parsed);

        Assert.Equal(challenge.Version, parsed!.Version);
        Assert.Equal(challenge.Flags, parsed.Flags);
        Assert.Equal(challenge.Nonce, parsed.Nonce);
        Assert.Equal(challenge.IssuedUtc, parsed.IssuedUtc);
        Assert.Equal(UninstallKeyMode.Rsa, parsed.Mode);
    }

    [Fact]
    public void Parse_DetectsTypo()
    {
        var text = Base32Crockford.Normalize(
            UninstallChallenge.Create(Hwid, UninstallKeyMode.Rsa).ToDisplayString());

        // התו הזה יושב בתוך ה-Nonce, כך שהשגיאה נתפסת על ידי ה-CRC
        // ולא על ידי בדיקת הגרסה שקודמת לו.
        var chars = text.ToCharArray();
        chars[25] = chars[25] == 'A' ? 'B' : 'A';

        Assert.False(UninstallChallenge.TryParse(new string(chars), out _, out var error));
        Assert.Contains("הקלדה", error);
    }

    [Fact]
    public void MatchesHwid_RejectsDifferentMachine()
    {
        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Rsa);

        Assert.True(challenge.MatchesHwid(Hwid));
        Assert.False(challenge.MatchesHwid("OTHERMACHINE0123456789AB"));
    }

    [Fact]
    public void DisplayString_IsGroupedAndReadable()
    {
        var text = UninstallChallenge.Create(Hwid, UninstallKeyMode.Rsa).ToDisplayString();

        Assert.Contains('-', text);
        Assert.DoesNotContain('U', text);
        Assert.All(text.Where(c => c != '-'), c => Assert.True(char.IsAsciiLetterOrDigit(c)));
    }
}

public class ChallengeResponseServiceTests
{
    private const string Hwid = "TESTHWID0123456789ABCDEF";

    private static readonly byte[] Secret = RandomNumberGenerator.GetBytes(32);

    [Fact]
    public void Hmac_ValidResponse_IsAccepted()
    {
        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Hmac);
        var response = ChallengeResponseService.GenerateHmacResponse(challenge, Secret);

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, HmacOptions(challenge));

        Assert.True(result.Granted);
    }

    [Fact]
    public void Hmac_WrongSecret_IsRejected()
    {
        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Hmac);
        var response = ChallengeResponseService.GenerateHmacResponse(
            challenge, RandomNumberGenerator.GetBytes(32));

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, HmacOptions(challenge));

        Assert.Equal(ChallengeValidation.BadResponse, result.Status);
    }

    [Fact]
    public void Rsa_ValidSignature_IsAccepted()
    {
        using var rsa = RSA.Create(2048);

        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Rsa);
        var response = ChallengeResponseService.GenerateRsaResponse(challenge, rsa);

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, new ChallengeValidationOptions
            {
                Hwid = Hwid,
                Mode = UninstallKeyMode.Rsa,
                ServerPublicKeyPem = rsa.ExportSubjectPublicKeyInfoPem(),
                ExpectedChallenge = challenge
            });

        Assert.True(result.Granted);
    }

    [Fact]
    public void Rsa_SignatureFromDifferentKey_IsRejected()
    {
        using var serverKey = RSA.Create(2048);
        using var attackerKey = RSA.Create(2048);

        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Rsa);
        var response = ChallengeResponseService.GenerateRsaResponse(challenge, attackerKey);

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, new ChallengeValidationOptions
            {
                Hwid = Hwid,
                Mode = UninstallKeyMode.Rsa,
                ServerPublicKeyPem = serverKey.ExportSubjectPublicKeyInfoPem(),
                ExpectedChallenge = challenge
            });

        Assert.Equal(ChallengeValidation.BadResponse, result.Status);
    }

    [Fact]
    public void ExpiredChallenge_IsRejected()
    {
        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Hmac);
        var response = ChallengeResponseService.GenerateHmacResponse(challenge, Secret);

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, HmacOptions(challenge),
            DateTimeOffset.UtcNow.AddHours(2));

        Assert.Equal(ChallengeValidation.Expired, result.Status);
    }

    [Fact]
    public void FutureChallenge_BeyondTolerance_IsRejected()
    {
        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Hmac);
        var response = ChallengeResponseService.GenerateHmacResponse(challenge, Secret);

        // המשתמש הזיז את השעון אחורה כדי להאריך את חלון התוקף
        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, HmacOptions(challenge),
            DateTimeOffset.UtcNow.AddHours(-2));

        Assert.Equal(ChallengeValidation.NotYetValid, result.Status);
    }

    [Fact]
    public void ChallengeFromOtherMachine_IsRejected()
    {
        var challenge = UninstallChallenge.Create("OTHERMACHINE0123456789AB", UninstallKeyMode.Hmac);
        var response = ChallengeResponseService.GenerateHmacResponse(challenge, Secret);

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, HmacOptions(challenge));

        Assert.Equal(ChallengeValidation.HwidMismatch, result.Status);
    }

    [Fact]
    public void ReplayedNonce_IsRejected()
    {
        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Hmac);
        var response = ChallengeResponseService.GenerateHmacResponse(challenge, Secret);

        var options = new ChallengeValidationOptions
        {
            Hwid = Hwid,
            Mode = UninstallKeyMode.Hmac,
            DeviceSecret = Secret,
            ExpectedChallenge = challenge,
            UsedNonces = [Convert.ToHexString(challenge.Nonce)]
        };

        var result = ChallengeResponseService.Validate(challenge.ToDisplayString(), response, options);

        Assert.Equal(ChallengeValidation.AlreadyUsed, result.Status);
    }

    [Fact]
    public void ResponseForDifferentChallenge_IsRejected()
    {
        var issued = UninstallChallenge.Create(Hwid, UninstallKeyMode.Hmac);
        var other = UninstallChallenge.Create(Hwid, UninstallKeyMode.Hmac);

        var response = ChallengeResponseService.GenerateHmacResponse(other, Secret);

        var result = ChallengeResponseService.Validate(
            other.ToDisplayString(), response, HmacOptions(issued));

        Assert.Equal(ChallengeValidation.NonceMismatch, result.Status);
    }

    [Fact]
    public void MissingKeyMaterial_IsReported()
    {
        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Hmac);

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), "ANYCODE", new ChallengeValidationOptions
            {
                Hwid = Hwid,
                Mode = UninstallKeyMode.Hmac,
                DeviceSecret = null,
                ExpectedChallenge = challenge
            });

        Assert.Equal(ChallengeValidation.MissingKeyMaterial, result.Status);
    }

    private static ChallengeValidationOptions HmacOptions(UninstallChallenge expected) => new()
    {
        Hwid = Hwid,
        Mode = UninstallKeyMode.Hmac,
        DeviceSecret = Secret,
        ExpectedChallenge = expected
    };
}
