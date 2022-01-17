using System;
using System.Runtime.InteropServices;
using CG.Framework.Attributes;
using CG.Framework.Plugin.Memory;

namespace CG.Memory;

[Flags]
internal enum ProcessAccessFlags : uint
{
    None = 0,
    Terminate = 0x00000001,
    CreateThread = 0x00000002,
    VirtualMemoryOperation = 0x00000008,
    VirtualMemoryRead = 0x00000010,
    VirtualMemoryWrite = 0x00000020,
    DuplicateHandle = 0x00000040,
    CreateProcess = 0x000000080,
    SetQuota = 0x00000100,
    SetInformation = 0x00000200,
    QueryInformation = 0x00000400,
    QueryLimitedInformation = 0x00001000,
    Synchronize = 0x00100000,
    All = 0x001F0FFF
}

[PluginInfo("CorrM", "Native", "Use current system API to read/write memory process")]
public class Native : MemoryPlugin
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UIntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(UIntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(UIntPtr hProcess, UIntPtr lpBaseAddress, [In] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process([In] UIntPtr processHandle, [Out] out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(UIntPtr hHandle);

    public override UIntPtr ProcessHandle { get; protected set; }
    public override bool Is64Bit { get; protected set; }
    public override bool IsSetup { get; protected set; }

    public static bool Is64BitProcess(UIntPtr processHandle)
    {
        return IsWow64Process(processHandle, out bool retVal) && !retVal;
    }

    public override void Setup(MemorySetupInfo info)
    {
        ProcessHandle = OpenProcess(ProcessAccessFlags.All, false, info.Process.Id);
        Is64Bit = Is64BitProcess(ProcessHandle);

        IsSetup = true;
    }

    public override bool ReadBytes(UIntPtr address, int size, out ReadOnlySpan<byte> buffer, out int numberOfBytesRead)
    {
        int cSize = size;
        var bytes = new byte[size];
        bool success = false;

        numberOfBytesRead = 0;
        buffer = ReadOnlySpan<byte>.Empty;

        try
        {
            while (true)
            {
                success = ReadProcessMemory(ProcessHandle, address, bytes, cSize, out numberOfBytesRead);
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 299 && numberOfBytesRead == 0 && cSize > 1) // ERROR_PARTIAL_COPY
                    {
                        --cSize;
                        continue;
                    }
                }
                else
                {
                    buffer = new ReadOnlySpan<byte>(bytes, 0, numberOfBytesRead);
                }

                return numberOfBytesRead == size && buffer.Length > 0;
            }
        }
        catch (Exception)
        {
            Console.WriteLine($"[ERR] Address = 0x{address.ToUInt64():X}, Size = {size}, NumberOfBytesRead = {numberOfBytesRead}.");
            Console.WriteLine($"[ERR] BytesLen = {bytes.Length}, CSize = {cSize}, success = {success}");
            throw;
        }
    }

    public override bool WriteBytes(UIntPtr address, byte[] buffer, out int numberOfBytesWritten)
    {
        WriteProcessMemory(ProcessHandle, address, buffer, buffer.Length, out numberOfBytesWritten);
        return numberOfBytesWritten == (uint)buffer.Length;
    }

    public override void Dispose()
    {
        base.Dispose();

        CloseHandle(ProcessHandle);
        GC.SuppressFinalize(this);
    }
}