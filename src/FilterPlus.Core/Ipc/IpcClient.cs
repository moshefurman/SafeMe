using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace FilterPlus.Core.Ipc;

/// <summary>
/// לקוח ה-IPC שמשמש את TrayApp ואת מסך ההסרה.
/// פרוטוקול: הודעת JSON אחת בשורה (NDJSON) מעל Named Pipe.
/// כל קריאה פותחת חיבור קצר וסוגרת אותו, כדי לא להחזיק משאבים בשירות.
/// </summary>
public sealed class IpcClient
{
    private readonly string _pipeName;

    public IpcClient(string? pipeName = null) => _pipeName = pipeName ?? IpcConstants.PipeName;

    /// <summary>שולח בקשה ומחזיר את התשובה. זורק אם השירות אינו זמין.</summary>
    public async Task<IpcResponse> SendAsync(string op, object? payload = null, CancellationToken ct = default)
    {
        await using var pipe = new NamedPipeClientStream(
            ".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        await pipe.ConnectAsync(IpcConstants.ConnectTimeoutMs, ct);

        var request = new IpcRequest
        {
            Op = op,
            Payload = payload is null
                ? null
                : JsonSerializer.SerializeToElement(payload, FilterPlusJson.Options)
        };

        var line = FilterPlusJson.Serialize(request) + "\n";
        var bytes = Encoding.UTF8.GetBytes(line);

        await pipe.WriteAsync(bytes, ct);
        await pipe.FlushAsync(ct);

        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 8192, leaveOpen: true);
        var responseLine = await reader.ReadLineAsync(ct);

        if (string.IsNullOrWhiteSpace(responseLine))
            throw new IOException("השירות סגר את החיבור ללא תשובה.");

        return FilterPlusJson.Deserialize<IpcResponse>(responseLine)
               ?? throw new IOException("תשובה לא תקינה מהשירות.");
    }

    /// <summary>שולח בקשה ומפענח את גוף התשובה לטיפוס המבוקש.</summary>
    public async Task<T?> SendAsync<T>(string op, object? payload = null, CancellationToken ct = default)
    {
        var response = await SendAsync(op, payload, ct);

        if (!response.Ok)
            throw new InvalidOperationException(response.Error ?? "הפעולה נכשלה.");

        if (response.Payload is null) return default;

        // ה-Payload מגיע כ-JsonElement לאחר הפענוח
        var element = (JsonElement)response.Payload;
        return element.Deserialize<T>(FilterPlusJson.Options);
    }

    /// <summary>בודק אם השירות מגיב, ללא זריקת חריגה.</summary>
    public async Task<bool> IsServiceAliveAsync(CancellationToken ct = default)
    {
        try
        {
            var response = await SendAsync(IpcOps.Ping, null, ct);
            return response.Ok;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
