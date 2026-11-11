using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace SafeMe.Core.DnsFilter;

/// <summary>
/// קריאה וכתיבה של הודעות DNS, במידה ששרת השמות המקומי צריך.
///
/// זה אינו מפענח כללי. הוא יודע שלושה דברים: לקרוא את השאלה, לבנות
/// תשובה קצרה משלו, ולשלוף את הכתובות מתשובה של שרת אחר. כל השאר
/// עובר כפי שהוא, בתים כמו שהתקבלו.
///
/// טהור ובלי רשת, כדי שכל מקרה קצה ייבדק בלי מכונה. הקלט מגיע
/// מהרשת, ולכן כל קריאה בודקת גבולות ושום דבר כאן אינו זורק.
/// </summary>
public static class DnsWire
{
    public const ushort TypeA = 1;
    public const ushort TypeAaaa = 28;
    public const ushort TypeSvcb = 64;
    public const ushort TypeHttps = 65;

    public const int RcodeOk = 0;
    public const int RcodeServerFailure = 2;
    public const int RcodeNameError = 3;

    private const int HeaderSize = 12;

    /// <summary>
    /// קורא את השאלה הראשונה. מחזיר false להודעה שאינה שאילתה תקינה.
    /// </summary>
    public static bool TryReadQuestion(
        ReadOnlySpan<byte> message, out string name, out ushort type, out int questionEnd)
    {
        name = "";
        type = 0;
        questionEnd = 0;

        if (message.Length < HeaderSize + 5) return false;

        // סיבית QR דלוקה פירושה תשובה. שרת שעונה על תשובות הוא לולאה.
        if ((message[2] & 0x80) != 0) return false;

        if (BinaryPrimitives.ReadUInt16BigEndian(message[4..]) != 1) return false;

        var builder = new StringBuilder();
        var offset = HeaderSize;

        while (true)
        {
            if (offset >= message.Length) return false;

            var length = message[offset];

            if (length == 0)
            {
                offset++;
                break;
            }

            // בשאלה אין דחיסה. מצביע כאן הוא הודעה פגומה או ניסיון לבלבל.
            if ((length & 0xC0) != 0) return false;

            if (offset + 1 + length > message.Length) return false;

            if (builder.Length > 0) builder.Append('.');

            for (var i = 0; i < length; i++)
            {
                var c = (char)message[offset + 1 + i];

                builder.Append(c is >= 'A' and <= 'Z' ? (char)(c + 32) : c);
            }

            offset += 1 + length;

            if (builder.Length > 253) return false;
        }

        if (offset + 4 > message.Length) return false;

        type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
        questionEnd = offset + 4;
        name = builder.ToString();

        return true;
    }

    /// <summary>
    /// תשובה בלי רשומות: "אין שם כזה", או "יש, אבל לא מהסוג הזה".
    /// </summary>
    public static byte[] BuildEmpty(ReadOnlySpan<byte> query, int questionEnd, int rcode)
    {
        var response = query[..questionEnd].ToArray();

        WriteResponseHeader(response, rcode, answers: 0);

        return response;
    }

    /// <summary>תשובה עם כתובת אחת. משמשת רק לשם הבדיקה העצמית.</summary>
    public static byte[] BuildAddress(ReadOnlySpan<byte> query, int questionEnd, IPAddress address, uint ttl)
    {
        var bytes = address.GetAddressBytes();
        var response = new byte[questionEnd + 12 + bytes.Length];

        query[..questionEnd].CopyTo(response);
        WriteResponseHeader(response, RcodeOk, answers: 1);

        var span = response.AsSpan(questionEnd);

        // מצביע לשם שבשאלה, שתמיד מתחיל מיד אחרי הכותרת
        span[0] = 0xC0;
        span[1] = HeaderSize;

        BinaryPrimitives.WriteUInt16BigEndian(span[2..], bytes.Length == 4 ? TypeA : TypeAaaa);
        BinaryPrimitives.WriteUInt16BigEndian(span[4..], 1);
        BinaryPrimitives.WriteUInt32BigEndian(span[6..], ttl);
        BinaryPrimitives.WriteUInt16BigEndian(span[10..], (ushort)bytes.Length);
        bytes.CopyTo(span[12..]);

        return response;
    }

    private static void WriteResponseHeader(Span<byte> message, int rcode, ushort answers)
    {
        // QR, ושומרים על RD כפי שנשאל. RA דלוק: אנחנו כן מעבירים הלאה.
        message[2] = (byte)(0x80 | (message[2] & 0x01));
        message[3] = (byte)(0x80 | (rcode & 0x0F));

        BinaryPrimitives.WriteUInt16BigEndian(message[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(message[6..], answers);
        BinaryPrimitives.WriteUInt16BigEndian(message[8..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(message[10..], 0);
    }

    public static bool IsTruncated(ReadOnlySpan<byte> message)
        => message.Length >= HeaderSize && (message[2] & 0x02) != 0;

    /// <summary>
    /// שולף את כל הכתובות מחלק התשובות, ומקצר את זמן החיים שלהן.
    ///
    /// כל הכתובות, בלי קשר לשם שהן רשומות עליו: אתר שמפנה ל-CDN עונה
    /// בשרשרת CNAME, והכתובת בסופה רשומה על שם אחר לגמרי. מי ששאל
    /// קיבל את כולן, ולכן כולן נפתחות.
    ///
    /// זמן החיים מקוצר במקום, כי ההיתר ב-WFP אינו נשמר לנצח. תשובה
    /// שהמחשב זוכר יומיים מפנה לכתובת שההיתר שלה כבר פג, והאתר נשבר
    /// בלי סיבה נראית לעין.
    ///
    /// מחזיר false להודעה פגומה. כתובות מהודעה כזו אינן נפתחות.
    /// </summary>
    public static bool TryReadAddresses(Span<byte> response, uint maxTtl, List<IPAddress> addresses)
    {
        if (response.Length < HeaderSize) return false;

        var questions = BinaryPrimitives.ReadUInt16BigEndian(response[4..]);
        var answers = BinaryPrimitives.ReadUInt16BigEndian(response[6..]);
        var offset = HeaderSize;

        for (var i = 0; i < questions; i++)
        {
            if (!TrySkipName(response, ref offset)) return false;

            offset += 4;
        }

        for (var i = 0; i < answers; i++)
        {
            if (!TrySkipName(response, ref offset)) return false;
            if (offset + 10 > response.Length) return false;

            var type = BinaryPrimitives.ReadUInt16BigEndian(response[offset..]);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(response[(offset + 4)..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(response[(offset + 8)..]);

            if (ttl > maxTtl)
                BinaryPrimitives.WriteUInt32BigEndian(response[(offset + 4)..], maxTtl);

            offset += 10;

            if (offset + length > response.Length) return false;

            if ((type == TypeA && length == 4) || (type == TypeAaaa && length == 16))
                addresses.Add(new IPAddress(response.Slice(offset, length)));

            offset += length;
        }

        return true;
    }

    private static bool TrySkipName(ReadOnlySpan<byte> message, ref int offset)
    {
        while (true)
        {
            if (offset >= message.Length) return false;

            var length = message[offset];

            if (length == 0)
            {
                offset++;
                return true;
            }

            // מצביע דחיסה: שני בתים, והשם נגמר כאן
            if ((length & 0xC0) == 0xC0)
            {
                offset += 2;
                return offset <= message.Length;
            }

            if ((length & 0xC0) != 0) return false;

            offset += 1 + length;
        }
    }

    /// <summary>
    /// האם זו כתובת שמותר לפתוח.
    ///
    /// 0.0.0.0 היא הדרך שבה שרת שמות מסווג אומר "חסום". לולאה מקומית
    /// ושידור אינם יעד של אתר, ושם שנפתר אליהם אינו סיבה לפתוח דבר.
    /// </summary>
    public static bool IsRoutable(IPAddress address)
    {
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return false;
        if (IPAddress.IsLoopback(address)) return false;
        if (address.Equals(IPAddress.Broadcast)) return false;

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var first = address.GetAddressBytes()[0];

            // 0.0.0.0/8 ושידור מרובה
            if (first == 0 || first >= 224) return false;
        }
        else if (address.IsIPv6Multicast)
        {
            return false;
        }

        return true;
    }
}
