using System.Buffers.Binary;
using System.Security.Cryptography;
using SafeMe.Core.Models;

namespace SafeMe.Core.Security;

/// <summary>
/// אתגר הסרה מקומי. מבנה בינארי של 22 בתים שמקודד ל-36 תווי Base32:
///
///   היסט 0  (1)  version
///   היסט 1  (1)  flags        bit0 = מצב RSA, bit1 = חירום אופליין
///   היסט 2  (8)  hwidHash     שמונת הבתים הראשונים של SHA256(HWID)
///   היסט 10 (4)  issuedMinutes  דקות יוניקס, UInt32 little-endian
///   היסט 14 (6)  nonce        אקראי קריפטוגרפי
///   היסט 20 (2)  crc16        על הבתים 0..19
/// </summary>
public sealed class UninstallChallenge
{
    public const int PayloadLength = 20;
    public const int TotalLength = 22;
    public const byte CurrentVersion = 1;

    public const byte FlagRsa = 0b0000_0001;
    public const byte FlagOfflineEmergency = 0b0000_0010;

    public byte Version { get; private init; } = CurrentVersion;
    public byte Flags { get; private init; }
    public byte[] HwidHash { get; private init; } = new byte[8];
    public DateTimeOffset IssuedUtc { get; private init; }
    public byte[] Nonce { get; private init; } = new byte[6];

    public UninstallKeyMode Mode => (Flags & FlagRsa) != 0 ? UninstallKeyMode.Rsa : UninstallKeyMode.Hmac;
    public bool IsOfflineEmergency => (Flags & FlagOfflineEmergency) != 0;

    /// <summary>יוצר אתגר חדש עבור מזהה החומרה הנתון.</summary>
    public static UninstallChallenge Create(string hwid, UninstallKeyMode mode, bool offlineEmergency = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hwid);

        byte flags = 0;
        if (mode == UninstallKeyMode.Rsa) flags |= FlagRsa;
        if (offlineEmergency) flags |= FlagOfflineEmergency;

        var nonce = new byte[6];
        RandomNumberGenerator.Fill(nonce);

        return new UninstallChallenge
        {
            Version = CurrentVersion,
            Flags = flags,
            HwidHash = ComputeHwidHash(hwid),
            // רזולוציית דקה: מקצרת את הקוד ומספיקה לחלון תוקף של 30 דקות
            IssuedUtc = DateTimeOffset.FromUnixTimeSeconds(
                DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60 * 60),
            Nonce = nonce
        };
    }

    /// <summary>שמונת הבתים הראשונים של SHA-256 על מזהה החומרה.</summary>
    public static byte[] ComputeHwidHash(string hwid)
    {
        var full = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(hwid.Trim().ToUpperInvariant()));
        return full[..8];
    }

    /// <summary>מייצר את 22 הבתים של האתגר, כולל CRC.</summary>
    public byte[] ToBytes()
    {
        var bytes = new byte[TotalLength];

        bytes[0] = Version;
        bytes[1] = Flags;
        HwidHash.AsSpan(0, 8).CopyTo(bytes.AsSpan(2, 8));

        var minutes = (uint)(IssuedUtc.ToUnixTimeSeconds() / 60);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(10, 4), minutes);

        Nonce.AsSpan(0, 6).CopyTo(bytes.AsSpan(14, 6));

        var crc = Crc16.Compute(bytes.AsSpan(0, PayloadLength));
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(20, 2), crc);

        return bytes;
    }

    /// <summary>הבתים שעליהם חותמים - ללא ה-CRC, שהוא בדיקת הקלדה בלבד.</summary>
    public byte[] ToSignedPayload() => ToBytes()[..PayloadLength];

    /// <summary>המחרוזת שמוצגת למשתמש, בקבוצות של 6 תווים.</summary>
    public string ToDisplayString() => Base32Crockford.Group(Base32Crockford.Encode(ToBytes()));

    public static bool TryParse(string text, out UninstallChallenge? challenge, out string? error)
    {
        challenge = null;
        error = null;

        if (string.IsNullOrWhiteSpace(text))
        {
            error = "קוד האתגר ריק.";
            return false;
        }

        if (!Base32Crockford.TryDecode(Base32Crockford.Normalize(text), out var bytes))
        {
            error = "קוד האתגר מכיל תווים לא חוקיים.";
            return false;
        }

        if (bytes.Length < TotalLength)
        {
            error = "קוד האתגר קצר מדי או חסר.";
            return false;
        }

        // Base32 עלול להוסיף בית ריפוד אחד בסוף; מתעלמים ממנו
        bytes = bytes[..TotalLength];

        if (bytes[0] != CurrentVersion)
        {
            error = $"גרסת אתגר לא נתמכת ({bytes[0]}).";
            return false;
        }

        var expectedCrc = Crc16.Compute(bytes.AsSpan(0, PayloadLength));
        var actualCrc = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(20, 2));

        if (expectedCrc != actualCrc)
        {
            error = "שגיאת הקלדה בקוד האתגר. בדוק שהקוד הועתק במלואו.";
            return false;
        }

        var minutes = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(10, 4));

        challenge = new UninstallChallenge
        {
            Version = bytes[0],
            Flags = bytes[1],
            HwidHash = bytes[2..10],
            IssuedUtc = DateTimeOffset.FromUnixTimeSeconds((long)minutes * 60),
            Nonce = bytes[14..20]
        };

        return true;
    }

    /// <summary>השוואת ה-Nonce בזמן קבוע, למניעת דליפת מידע בתזמון.</summary>
    public bool NonceEquals(UninstallChallenge other) =>
        CryptographicOperations.FixedTimeEquals(Nonce, other.Nonce);

    public bool MatchesHwid(string hwid) =>
        CryptographicOperations.FixedTimeEquals(HwidHash, ComputeHwidHash(hwid));
}
