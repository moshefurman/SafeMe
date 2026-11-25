using System.Text;

namespace FilterPlus.Core.Security;

/// <summary>
/// קידוד Base32 בתקן Crockford: ללא התווים I, L, O, U כדי למנוע בלבול
/// כשמקריאים קוד בטלפון למוקד. הפענוח סלחני - מתעלם ממקפים, רווחים ורישיות,
/// וממפה I ו-L ל-1, ו-O ל-0.
/// </summary>
public static class Base32Crockford
{
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    private static readonly int[] Reverse = BuildReverseTable();

    private static int[] BuildReverseTable()
    {
        var table = new int[128];
        Array.Fill(table, -1);

        for (var i = 0; i < Alphabet.Length; i++)
        {
            table[Alphabet[i]] = i;
            table[char.ToLowerInvariant(Alphabet[i])] = i;
        }

        // מיפוי תווים מבלבלים
        table['I'] = table['i'] = table['L'] = table['l'] = 1;
        table['O'] = table['o'] = 0;
        table['U'] = table['u'] = -1; // U נשאר פסול במכוון

        return table;
    }

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return string.Empty;

        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bits = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(Alphabet[(buffer >> bits) & 0x1F]);
            }
        }

        if (bits > 0)
            sb.Append(Alphabet[(buffer << (5 - bits)) & 0x1F]);

        return sb.ToString();
    }

    public static byte[] Decode(string text)
    {
        if (string.IsNullOrEmpty(text)) return [];

        var output = new List<byte>(text.Length * 5 / 8 + 1);
        var buffer = 0;
        var bits = 0;

        foreach (var ch in text)
        {
            if (ch is '-' or ' ' or '\t' or '\r' or '\n') continue;
            if (ch >= Reverse.Length) throw new FormatException($"תו לא חוקי בקוד: '{ch}'");

            var value = Reverse[ch];
            if (value < 0) throw new FormatException($"תו לא חוקי בקוד: '{ch}'");

            buffer = (buffer << 5) | value;
            bits += 5;

            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)((buffer >> bits) & 0xFF));
            }
        }

        return output.ToArray();
    }

    public static bool TryDecode(string text, out byte[] data)
    {
        try
        {
            data = Decode(text);
            return true;
        }
        catch (FormatException)
        {
            data = [];
            return false;
        }
    }

    /// <summary>מחלק את הקוד לקבוצות עם מקפים כדי שיהיה קריא בטלפון.</summary>
    public static string Group(string code, int groupSize = 6)
    {
        if (groupSize <= 0 || code.Length <= groupSize) return code;

        var sb = new StringBuilder(code.Length + code.Length / groupSize);

        for (var i = 0; i < code.Length; i++)
        {
            if (i > 0 && i % groupSize == 0) sb.Append('-');
            sb.Append(code[i]);
        }

        return sb.ToString();
    }

    /// <summary>מנקה קלט משתמש: מסיר מקפים ורווחים ומעלה לאותיות גדולות.</summary>
    public static string Normalize(string input) =>
        new(input.Where(c => !char.IsWhiteSpace(c) && c != '-').Select(char.ToUpperInvariant).ToArray());
}
