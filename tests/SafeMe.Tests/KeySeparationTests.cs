using System.Security.Cryptography;
using SafeMe.Core.Models;
using SafeMe.Core.Policy;
using SafeMe.Core.Security;
using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// הפרדת מפתח ההיתרים ממפתח המדיניות.
///
/// זו כל ההגנה מאחורי "להחמיר כן, להסיר לא". בלעדיה כל יכולת לחתום
/// מדיניות היא גם יכולת להקל אותה מתחת לרצפה, ושרת שנפרץ — או שרת
/// מזויף שהמחשב הופנה אליו — היה יכול פשוט לשלוח את אותו מפתח
/// בשני השדות.
///
/// הסוכן אוכף את זה בעצמו, ואינו מסתמך על כך שהשרת אכף.
/// </summary>
public class KeySeparationTests
{
    private const string Hwid = "HWID0000000000000000000001";

    private static string NewKeyPem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportSubjectPublicKeyInfoPem();
    }

    [Fact]
    public void שני_מפתחות_שונים_עוברים()
    {
        var result = LooseningGrantValidator.CheckKeySeparation(NewKeyPem(), NewKeyPem());

        Assert.True(result.Ok);
        Assert.Equal(GrantValidation.Ok, result.Status);
    }

    [Fact]
    public void אותו_מפתח_בשני_השדות_נדחה()
    {
        var pem = NewKeyPem();

        var result = LooseningGrantValidator.CheckKeySeparation(pem, pem);

        Assert.False(result.Ok);
        Assert.Equal(GrantValidation.KeyNotSeparate, result.Status);
    }

    /// <summary>
    /// אותו מפתח שהגיע משני נתיבים עלול להיבדל בסופי שורה בלבד.
    /// השוואת טקסט נאיבית הייתה מכריזה עליהם כשונים, וההפרדה הייתה
    /// נראית קיימת בזמן שאינה.
    /// </summary>
    [Fact]
    public void אותו_מפתח_בעטיפה_שונה_עדיין_נדחה()
    {
        var pem = NewKeyPem();
        var reWrapped = pem.Replace("\r\n", "\n").Replace("\n", "\r\n") + "\n  ";

        var result = LooseningGrantValidator.CheckKeySeparation(pem, reWrapped);

        Assert.False(result.Ok);
        Assert.Equal(GrantValidation.KeyNotSeparate, result.Status);
    }

    [Fact]
    public void בלי_מפתח_היתרים_נדחה()
    {
        Assert.Equal(
            GrantValidation.KeyMissing,
            LooseningGrantValidator.CheckKeySeparation(null, NewKeyPem()).Status);

        Assert.Equal(
            GrantValidation.KeyMissing,
            LooseningGrantValidator.CheckKeySeparation("   ", NewKeyPem()).Status);
    }

    /// <summary>
    /// מחשב שנרשם מול שרת ישן, שעדיין אינו שולח מפתח מדיניות בנפרד,
    /// לא ייחסם. אין מול מה להשוות, ושאר האימותים בהיתר עדיין חלים.
    /// </summary>
    [Fact]
    public void בלי_מפתח_מדיניות_להשוואה_עובר()
    {
        Assert.True(LooseningGrantValidator.CheckKeySeparation(NewKeyPem(), null).Ok);
    }

    // ─────────────────────────────────────── מסלול ההסרה עצמו

    /// <summary>
    /// קוד הסרה תקין לחלוטין, חתום במפתח הנכון — אך אותו מפתח הוא
    /// גם מפתח המדיניות. נדחה, כי אחרת כל מי שיכול לחתום מדיניות
    /// יכול גם להסיר כל מחשב בשטח.
    ///
    /// זה בדיוק המצב שהיה בקוד עד עכשיו.
    /// </summary>
    [Fact]
    public void קוד_הסרה_תקין_נדחה_כשהמפתח_זהה_למדיניות()
    {
        using var key = RSA.Create(2048);
        var pem = key.ExportSubjectPublicKeyInfoPem();

        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Rsa);
        var response = ChallengeResponseService.GenerateRsaResponse(challenge, key);

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, new ChallengeValidationOptions
            {
                Hwid = Hwid,
                Mode = UninstallKeyMode.Rsa,
                UninstallPublicKeyPem = pem,
                PolicyPublicKeyPem = pem,
                ExpectedChallenge = challenge
            });

        Assert.False(result.Granted);
        Assert.Equal(ChallengeValidation.KeyNotSeparate, result.Status);
    }

    [Fact]
    public void אותו_קוד_מתקבל_כשהמפתחות_נפרדים()
    {
        using var uninstallKey = RSA.Create(2048);
        using var policyKey = RSA.Create(2048);

        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Rsa);
        var response = ChallengeResponseService.GenerateRsaResponse(challenge, uninstallKey);

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, new ChallengeValidationOptions
            {
                Hwid = Hwid,
                Mode = UninstallKeyMode.Rsa,
                UninstallPublicKeyPem = uninstallKey.ExportSubjectPublicKeyInfoPem(),
                PolicyPublicKeyPem = policyKey.ExportSubjectPublicKeyInfoPem(),
                ExpectedChallenge = challenge
            });

        Assert.True(result.Granted);
    }

    /// <summary>
    /// מצב HMAC אינו נוגע במפתחות ציבוריים כלל, ולכן בדיקת ההפרדה
    /// לא אמורה לחסום אותו.
    /// </summary>
    [Fact]
    public void מצב_HMAC_אינו_מושפע()
    {
        var secret = RandomNumberGenerator.GetBytes(32);

        var challenge = UninstallChallenge.Create(Hwid, UninstallKeyMode.Hmac);
        var response = ChallengeResponseService.GenerateHmacResponse(challenge, secret);

        var result = ChallengeResponseService.Validate(
            challenge.ToDisplayString(), response, new ChallengeValidationOptions
            {
                Hwid = Hwid,
                Mode = UninstallKeyMode.Hmac,
                DeviceSecret = secret,
                ExpectedChallenge = challenge
            });

        Assert.True(result.Granted);
    }
}
