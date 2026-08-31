using System.Text.Json;

using SafeMe.Core;
using SafeMe.Core.Models;

namespace SafeMe.Tests;

/// <summary>
/// השדרוג מ-RSA ל-HMAC דרך הפעימה.
///
/// המצב נקבע ברישום, והתקנה מעל התקנה קיימת אינה נרשמת מחדש. כלומר
/// מחשב שנרשם לפני שהשרת ידע לגזור סודות היה נשאר עם קוד הסרה בן
/// שש מאות תווים לנצח — וזה נצפה בשטח, אחרי שהכול כבר הוגדר.
///
/// מה שנבדק כאן הוא הגשר עצמו: ששני הצדדים מסכימים על הבתים שעוברים
/// ברשת. כשל כאן אינו מתפוצץ — הוא מייצר סוכן ששומר null בשקט,
/// וממשיך להנפיק את הקוד הארוך.
/// </summary>
public class UninstallKeyUpgradeTests
{
    /// <summary>
    /// מה שהשרת באמת שולח, מילה במילה מ-device.ts.
    ///
    /// לא "Hmac" שהומצא כאן לצורך הבדיקה: הצורה הזו היא הטענה.
    /// </summary>
    private const string ServerPayload = """
        {
          "ok": true,
          "serverUtc": "2026-08-31T09:00:00.000Z",
          "policyEtag": "v12",
          "licenseValid": true,
          "uninstallKeyMode": "Hmac",
          "deviceSecret": "SE4x7XrDWJgWfOZUOFbSegpmaJV+ZBljdobLaKYXLAc=",
          "commands": []
        }
        """;

    [Fact]
    public void Heartbeat_carries_the_upgrade()
    {
        var r = JsonSerializer.Deserialize<HeartbeatResponse>(ServerPayload, SafeMeJson.Options);

        Assert.NotNull(r);

        /*
         * הקריאה הזו היא כל הבדיקה.
         *
         * הממיר רשום עם מדיניות camelCase, והשרת שולח PascalCase.
         * אם הפענוח אינו סובלני לאותיות, השדה יישאר null — והסוכן
         * פשוט יתעלם מהשדרוג בשקט מוחלט, בלי שגיאה ובלי לוג.
         */
        Assert.Equal(UninstallKeyMode.Hmac, r!.UninstallKeyMode);
        // HMAC-SHA256, כפי שגזירת הסוד בשרת מייצרת אותו
        Assert.Equal(32, Convert.FromBase64String(r.DeviceSecret!).Length);
    }

    [Fact]
    public void Ordinary_heartbeat_carries_no_secret()
    {
        /*
         * פעימה רגילה חייבת להשאיר את השדה ריק.
         *
         * ברירת מחדל שאינה null הייתה מפילה כל מחשב שנשאר ב-RSA
         * למצב HMAC בלי סוד — כלומר נעילה מוחלטת, שגרועה מקוד ארוך.
         */
        var r = JsonSerializer.Deserialize<HeartbeatResponse>(
            """{"ok":true,"serverUtc":"2026-08-31T09:00:00.000Z","commands":[]}""",
            SafeMeJson.Options);

        Assert.Null(r!.UninstallKeyMode);
        Assert.Null(r.DeviceSecret);
    }
}
