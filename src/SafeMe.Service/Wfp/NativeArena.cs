using System.Runtime.InteropServices;

namespace SafeMe.Service.Wfp;

/// <summary>
/// אזור זיכרון נייטיבי זמני. מבני WFP מכילים מצביעים שחייבים להישאר בתוקף
/// עד לחזרה מקריאת ה-API, ולכן מרכזים את כל ההקצאות ומשחררים אותן יחד.
/// </summary>
internal sealed class NativeArena : IDisposable
{
    private readonly List<IntPtr> _allocations = new();
    private bool _disposed;

    public IntPtr Alloc(int size)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var ptr = Marshal.AllocHGlobal(size);
        _allocations.Add(ptr);

        return ptr;
    }

    public IntPtr AllocStruct<T>(T value) where T : struct
    {
        var ptr = Alloc(Marshal.SizeOf<T>());
        Marshal.StructureToPtr(value, ptr, false);

        return ptr;
    }

    public IntPtr AllocBytes(ReadOnlySpan<byte> data)
    {
        var ptr = Alloc(data.Length);
        Marshal.Copy(data.ToArray(), 0, ptr, data.Length);

        return ptr;
    }

    public IntPtr AllocUInt64(ulong value)
    {
        var ptr = Alloc(sizeof(ulong));
        Marshal.WriteInt64(ptr, unchecked((long)value));

        return ptr;
    }

    /// <summary>מקצה מערך של מבנים רציף בזיכרון ומחזיר מצביע לתחילתו.</summary>
    public IntPtr AllocArray<T>(IReadOnlyList<T> items) where T : struct
    {
        if (items.Count == 0) return IntPtr.Zero;

        var elementSize = Marshal.SizeOf<T>();
        var ptr = Alloc(elementSize * items.Count);

        for (var i = 0; i < items.Count; i++)
            Marshal.StructureToPtr(items[i], ptr + i * elementSize, false);

        return ptr;
    }

    public void Dispose()
    {
        if (_disposed) return;

        foreach (var ptr in _allocations)
            Marshal.FreeHGlobal(ptr);

        _allocations.Clear();
        _disposed = true;
    }
}
