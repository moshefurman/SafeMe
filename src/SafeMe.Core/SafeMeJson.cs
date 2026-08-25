using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SafeMe.Core;

/// <summary>הגדרות סריאליזציה אחידות לכל רכיבי המערכת (IPC, שרת, קבצי מצב).</summary>
public static class SafeMeJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        // מונע בריחת תווים עבריים ל-\uXXXX בלוגים ובקבצי מצב
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static readonly JsonSerializerOptions Indented = new(Options) { WriteIndented = true };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);

    public static T? Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);

    public static bool TryDeserialize<T>(string json, out T? value)
    {
        try
        {
            value = JsonSerializer.Deserialize<T>(json, Options);
            return value is not null;
        }
        catch (JsonException)
        {
            value = default;
            return false;
        }
    }
}
