using System.Security.Cryptography;
using SafeMe.Core.Policy;
using Xunit;

namespace SafeMe.Tests;

/// <summary>
/// הפרדת מפתח ההיתרים ממפתח המדיניות.
///
/// זו כל ההגנה מאחורי "להחמיר כן, להסיר לא". בלעדיה כל יכולת לחתום
/// מדיניות היא גם יכולת להקל אותה מתחת לרצפה, ושרת שנפרץ — או שרת
/// מזויף שהמכשיר הופנה אליו — היה יכול פשוט לשלוח את אותו מפתח
/// בשני השדות.
///
/// הסוכן אוכף את זה בעצמו, ואינו מסתמך על כך שהשרת אכף.
/// </summary>
public class KeySeparationTests
{
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
    /// מכשיר שנרשם מול שרת ישן, שעדיין אינו שולח מפתח מדיניות בנפרד,
    /// לא ייחסם. אין מול מה להשוות, ושאר האימותים בהיתר עדיין חלים.
    /// </summary>
    [Fact]
    public void בלי_מפתח_מדיניות_להשוואה_עובר()
    {
        Assert.True(LooseningGrantValidator.CheckKeySeparation(NewKeyPem(), null).Ok);
    }
}
