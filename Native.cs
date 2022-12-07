using System;
using System.Runtime.InteropServices;
using CG.Framework.Attributes;
using CG.Framework.Helper;
using CG.Framework.Helper.Platform;
using CG.Framework.Plugin.Memory;

namespace CG.Memory;

[PluginInfo("CorrM", "Native", "Use current system API to read/write memory process", "https://github.com/CheatGear", "https://github.com/CheatGear/Memory.Native")]
public class Native : MemoryPlugin
{
    public override Version TargetFrameworkVersion { get; } = new(3, 0, 0);
    public override Version PluginVersion { get; } = new(3, 0, 0);

    protected override bool OnTargetChange()
    {
        ProcessHandle = Win32.OpenProcess(Win32.ProcessAccessFlags.All, false, CurrentTarget.Process.Id);
        Is64Bit = UtilsExtensions.Is64BitProcess(ProcessHandle);

        return IsValidProcessHandle();
    }

    public override bool ReadBytes(UIntPtr address, int size, out byte[] buffer, out int numberOfBytesRead)
    {
        int cSize = size;
        var bytes = new byte[size];

        while (true)
        {
            bool success = Win32.ReadProcessMemory(ProcessHandle, address, bytes, cSize, out numberOfBytesRead);
            if (!success)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 299 && numberOfBytesRead == 0 && cSize > 1) // ERROR_PARTIAL_COPY
                {
                    --cSize;
                    continue;
                }
            }

            buffer = numberOfBytesRead < 0 || numberOfBytesRead > bytes.Length
                ? bytes
                : bytes[..numberOfBytesRead];
            break;
        }

        bool allRead = numberOfBytesRead == size && buffer.Length > 0;
        numberOfBytesRead = cSize;

        return allRead;
    }

    public override bool WriteBytes(UIntPtr address, byte[] buffer, out int numberOfBytesWritten)
    {
        Win32.WriteProcessMemory(ProcessHandle, address, buffer, buffer.Length, out numberOfBytesWritten);
        return numberOfBytesWritten == (uint)buffer.Length;
    }

    protected override void OnDispose()
    {
    }
}
