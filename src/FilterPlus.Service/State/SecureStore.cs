using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using FilterPlus.Core;

namespace FilterPlus.Service.State;

/// <summary>
/// קריאה וכתיבה של קבצי מצב מוצפנים ב-DPAPI בהיקף מכונה.
///
/// DPAPI-Machine נבחר כדי שהשירות יוכל לקרוא את המצב בהפעלה מוקדמת,
/// לפני שמשתמש כלשהו התחבר. חשוב להבין את המגבלה: מנהל מערכת על אותה מכונה
/// יכול לפענח את התוכן. לכן הסוד מוגן גם ב-ACL, ומצב ההסרה המומלץ הוא RSA
/// שאינו מצריך שמירת סוד כלל.
/// </summary>
[SupportedOSPlatform("windows")]
public static class SecureStore
{
    /// <summary>אנטרופיה נוספת שקושרת את ההצפנה למוצר הזה בלבד.</summary>
    private static readonly byte[] Entropy = "FilterPlus/state/v1"u8.ToArray();

    public static void Write<T>(string path, T value)
    {
        var json = FilterPlusJson.Serialize(value);
        var plain = Encoding.UTF8.GetBytes(json);
        var cipher = ProtectedData.Protect(plain, Entropy, DataProtectionScope.LocalMachine);

        // כתיבה אטומית: קובץ זמני ואז החלפה, כדי שקריסה באמצע לא תשאיר מצב חלקי
        var temp = path + ".tmp";

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(temp, cipher);
        File.Move(temp, path, overwrite: true);
    }

    public static T? Read<T>(string path) where T : class
    {
        if (!File.Exists(path)) return null;

        try
        {
            var cipher = File.ReadAllBytes(path);
            var plain = ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.LocalMachine);

            return FilterPlusJson.Deserialize<T>(Encoding.UTF8.GetString(plain));
        }
        catch (CryptographicException)
        {
            // הקובץ נערך, הועתק ממכונה אחרת, או נפגם
            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>מחזיר true אם הקובץ קיים אך אינו ניתן לפענוח, כלומר נפגם או שונה.</summary>
    public static bool IsCorrupted(string path)
    {
        if (!File.Exists(path)) return false;

        try
        {
            var cipher = File.ReadAllBytes(path);
            ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.LocalMachine);

            return false;
        }
        catch (Exception)
        {
            return true;
        }
    }
}
