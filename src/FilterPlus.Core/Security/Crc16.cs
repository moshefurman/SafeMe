namespace FilterPlus.Core.Security;

/// <summary>
/// CRC-16/CCITT-FALSE (פולינום 0x1021, ערך התחלתי 0xFFFF).
/// משמש לזיהוי שגיאות הקלדה באתגר לפני שמפעילים קריפטוגרפיה כבדה.
/// זו בדיקת שלמות בלבד ולא מנגנון אבטחה.
/// </summary>
public static class Crc16
{
    private static readonly ushort[] Table = BuildTable();

    private static ushort[] BuildTable()
    {
        var table = new ushort[256];

        for (var i = 0; i < 256; i++)
        {
            var crc = (ushort)(i << 8);

            for (var bit = 0; bit < 8; bit++)
                crc = (crc & 0x8000) != 0 ? (ushort)((crc << 1) ^ 0x1021) : (ushort)(crc << 1);

            table[i] = crc;
        }

        return table;
    }

    public static ushort Compute(ReadOnlySpan<byte> data)
    {
        ushort crc = 0xFFFF;

        foreach (var b in data)
            crc = (ushort)((crc << 8) ^ Table[((crc >> 8) ^ b) & 0xFF]);

        return crc;
    }
}
