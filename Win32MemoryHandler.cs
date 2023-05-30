using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using CG.SDK.Dotnet.Helper;
using CG.SDK.Dotnet.Helper.Platform;
using CG.SDK.Dotnet.Plugin.Target;

namespace CG.Memory;

public sealed class Win32MemoryHandler : IMemoryHandler
{
    private readonly Native _target;
    private readonly int _memoryBasicInformationSize;
    private readonly Win32.NtQueryVirtualMemory _ntQueryVirtualMemory;
    private nint _processHandle;

    public Win32MemoryHandler(Native target)
    {
        _target = target;
        _memoryBasicInformationSize = Marshal.SizeOf<Win32.MemoryBasicInformation>();
        _ntQueryVirtualMemory = Win32.GetProcAddressDlg<Win32.NtQueryVirtualMemory>("ntdll.dll", "NtQueryVirtualMemory");
        _processHandle = nint.Zero;
    }

    public void OnTargetReady(nint processHandle)
    {
        _processHandle = processHandle;
    }

    public void OnTargetFree()
    {
    }

    /// <inheritdoc />
    public bool IsBadAddress(nuint address)
    {
        return address.IsNull()
               || address < _target.GetMinValidAddress()
               || address > _target.GetMaxValidAddress();
    }

    /// <inheritdoc />
    public bool IsStaticAddress(nuint address)
    {
        /*
         * Thanks To Roman_Ablo @ GuidedHacking
         * https://guidedhacking.com/threads/hyperscan-fast-vast-memory-scanner.9659/
         * Converted to C# by CorrM
         */

        if (_ntQueryVirtualMemory is null)
            throw new NullReferenceException("'_ntQueryVirtualMemory' can't be null");

        if (!_target.IsValidTarget())
            throw new Exception("Target process is not valid");

        if (address == nuint.Zero)
            return false;

        ulong length = 0;
        using var sectionInformation = new StructAllocator<Win32.SectionInfo>();

        int retStatus = _ntQueryVirtualMemory(
            _processHandle,
            address,
            Win32.MemoryInformationClass.MemoryMappedFilenameInformation,
            sectionInformation.UnManagedPtr.ToUIntPtr(),
            (ulong)Marshal.SizeOf<Win32.SectionInfo>(),
            ref length);

        // 32bit game
        if (!_target.Process64Bit)
            return Win32.NtSuccess(retStatus);

        if (!Win32.NtSuccess(retStatus))
            return false;

        sectionInformation.Update();
        string deviceName = sectionInformation.ManagedStruct.SzData;

        /*
        string filePath = new string(deviceName);
        for (int i = 0; i < 3; i++)
            filePath = filePath[(filePath.IndexOf('\\') + 1)..];
        filePath = filePath.Trim('\0');
        */

        IEnumerable<string> drivesLetter = DriveInfo.GetDrives().Select(d => d.Name.Replace("\\", ""));
        foreach (string driveLetter in drivesLetter)
        {
            var sb = new StringBuilder(64);
            _ = Win32.QueryDosDevice(driveLetter, sb, 64 * 2); // * 2 Unicode

            if (deviceName.Contains(sb.ToString()))
                return true;
        }

        return false;
    }

    /// <inheritdoc />
    public bool IsValidRemoteAddress(nuint address)
    {
        if (address == nuint.Zero || IsBadAddress(address))
            return false;

        bool valid = Win32.VirtualQueryEx(
            _processHandle,
            address,
            out Win32.MemoryBasicInformation info,
            (uint)_memoryBasicInformationSize
        ) == _memoryBasicInformationSize;
        if (!valid)
            return false;

        return (info.Protect & Win32.MemoryProtection.PageNoAccess) == 0;
    }

    /// <inheritdoc />
    public bool ReadBytes(nuint address, in Span<byte> bytes, int size, out int numberOfBytesRead)
    {
        ref byte bytesReference = ref MemoryMarshal.AsRef<byte>(bytes);

        // You can pass `ref MemoryMarshal.AsRef<byte>(bytes)` to the function directly
        return Win32.ReadProcessMemory(_processHandle, address, ref bytesReference, size, out numberOfBytesRead);
    }

    /// <inheritdoc />
    public bool WriteBytes(nuint address, in ReadOnlySpan<byte> bytes, int size, out int numberOfBytesWritten)
    {
        ref readonly byte bytesReference = ref MemoryMarshal.AsRef<byte>(bytes);

        return Win32.WriteProcessMemory(_processHandle, address, in bytesReference, bytes.Length, out numberOfBytesWritten);
    }
}
