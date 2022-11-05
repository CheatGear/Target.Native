using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using CG.Framework.Attributes;
using CG.Framework.Helper;
using CG.Framework.Helper.Platform;
using CG.Framework.Plugin.Memory;

namespace CG.Memory;

[PluginInfo("CorrM", "Native", "Use current system API to read/write memory process", "https://github.com/CheatGear", "https://github.com/CheatGear/Memory.Native")]
public class Native : MemoryPlugin
{
    private static Win32.NtQueryVirtualMemory? _ntQueryVirtualMemory;

    private MemoryTargetInfo _targetInfo;
    private IntPtr _pHandle;
    private Win32.SystemInfo _sysInfo;
    private int _memoryBasicInformationSize;

    public override Version TargetFrameworkVersion { get; } = new(3, 0, 0);
    public override Version PluginVersion { get; } = new(3, 0, 0);

    private UIntPtr GameStartAddress()
    {
        return _sysInfo.MinimumApplicationAddress;
    }

    private UIntPtr GameEndAddress()
    {
        return _sysInfo.MaximumApplicationAddress;
    }

    private bool ValidTargetHandle()
    {
        return _pHandle != IntPtr.Zero && _pHandle != Win32.InvalidHandleValue;
    }

    private void Clean()
    {
        // Suspend games case an Exception
        try
        {
            if (ValidTargetHandle())
                Win32.CloseHandle(_pHandle);
        }
        catch (Exception)
        {
            // ignored
        }
    }

    protected override bool OnInit()
    {
        _memoryBasicInformationSize = Marshal.SizeOf<Win32.MemoryBasicInformation>();
        Win32.GetSystemInfo(out _sysInfo);

        return true;
    }

    protected override bool OnTargetChange(MemoryTargetInfo targetInfo)
    {
        _targetInfo = targetInfo;

        Clean();

        _pHandle = Win32.OpenProcess(Win32.ProcessAccessFlags.All, false, targetInfo.Process.Id);
        Is64Bit = UtilsExtensions.Is64BitProcess(_pHandle);
        _ntQueryVirtualMemory = Win32.GetProcAddress<Win32.NtQueryVirtualMemory>("ntdll.dll", "NtQueryVirtualMemory");

        return ValidTargetHandle();
    }

    public override bool ReadBytes(UIntPtr address, int size, out byte[] buffer, out int numberOfBytesRead)
    {
        int cSize = size;
        var bytes = new byte[size];

        while (true)
        {
            bool success = Win32.ReadProcessMemory(_pHandle, address, bytes, cSize, out numberOfBytesRead);
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
        Win32.WriteProcessMemory(_pHandle, address, buffer, buffer.Length, out numberOfBytesWritten);
        return numberOfBytesWritten == (uint)buffer.Length;
    }

    public override MemoryRegionInfo? GetMemoryRegion(UIntPtr address)
    {
        // Get Region information
        bool valid = Win32.VirtualQueryEx(
            _pHandle,
            address,
            out Win32.MemoryBasicInformation info,
            (uint)_memoryBasicInformationSize
        ) == _memoryBasicInformationSize;

        if (!valid)
            return null;

        var region = new MemoryRegionInfo()
        {
            Address = info.BaseAddress,
            Size = info.RegionSize.ToUInt64(),
            State = (int)info.State,
            Protect = (int)info.Protect,
            Type = (int)info.Type,
        };

        return region;
    }

    public override MemoryModuleInfo? GetMainModule()
    {
        ProcessModule? processModule;

        try
        {
            processModule = _targetInfo.Process.MainModule;
            if (processModule is null)
                return null;
        }
        catch (Exception)
        {
            return null;
        }

        return new MemoryModuleInfo()
        {
            Address = processModule.BaseAddress,
            Size = (uint)processModule.ModuleMemorySize,
            Name = Path.GetFileName(processModule.FileName) ?? string.Empty,
            Path = processModule.FileName ?? string.Empty
        };
    }

    public override List<MemoryModuleInfo> GetModulesList()
    {
        var ret = new List<MemoryModuleInfo>();
        // To Avoid Some Games not share it's modules, or could be emulator game
        try
        {
            IntPtr hSnap = Win32.CreateToolhelp32Snapshot(Win32.SnapshotFlags.Module | Win32.SnapshotFlags.Module32, _targetInfo.Process.Id);
            if (hSnap != Win32.InvalidHandleValue)
            {
                var modEntry = new Win32.ModuleEntry32()
                {
                    DwSize = (uint)Marshal.SizeOf(typeof(Win32.ModuleEntry32))
                };

                if (Win32.Module32First(hSnap, ref modEntry))
                {
                    do
                    {
                        var mod = new MemoryModuleInfo()
                        {
                            Handle = modEntry.HModule,
                            Address = modEntry.ModBaseAddr,
                            Size = modEntry.ModBaseSize,
                            Name = modEntry.SzModule,
                            Path = modEntry.SzExePath
                        };
                        ret.Add(mod);
                    } while (Win32.Module32Next(hSnap, ref modEntry));
                }
            }

            Win32.CloseHandle(hSnap);
        }
        catch
        {
            // Ignore
        }

        return ret;
    }

    public override bool IsBadAddress(UIntPtr uIntPtr)
    {
        return uIntPtr.ToUInt64() < GameStartAddress().ToUInt64() || uIntPtr.ToUInt64() > GameEndAddress().ToUInt64();
    }

    public override bool IsValidRemoteAddress(UIntPtr remoteAddress)
    {
        // TODO: Very bad when called in hot-path
        if (remoteAddress == UIntPtr.Zero || IsBadAddress(remoteAddress))
            return false;

        if (Win32.VirtualQueryEx(_pHandle, remoteAddress, out Win32.MemoryBasicInformation info, (uint)_memoryBasicInformationSize) != 0)
            return info.Protect != 0 && (info.Protect & Win32.MemoryProtection.PageNoAccess) == 0;

        return false;
    }

    public override bool SuspendProcess()
    {
        return Win32.NtSuspendProcess(_pHandle) >= 0;
    }

    public override bool ResumeProcess()
    {
        return Win32.NtResumeProcess(_pHandle) >= 0;
    }

    public override bool TerminateProcess()
    {
        return Win32.NtTerminateProcess(_pHandle, 0) >= 0;
    }

    public override bool IsStaticAddress(UIntPtr address)
    {
        /*
         * Thanks To Roman_Ablo @ GuidedHacking
         * https://guidedhacking.com/threads/hyperscan-fast-vast-memory-scanner.9659/
         * Converted to C# By CorrM
         */

        if (_ntQueryVirtualMemory is null)
            throw new NullReferenceException("'_ntQueryVirtualMemory' can't be null");

        if (!ValidTargetHandle())
            throw new Exception("Target process is not valid");

        if (address == UIntPtr.Zero)
            return false;

        ulong length = 0;
        using var sectionInformation = new StructAllocator<Win32.SectionInfo>();

        int retStatus = _ntQueryVirtualMemory(
            (UIntPtr)_pHandle.ToNum(),
            address,
            Win32.MemoryInformationClass.MemoryMappedFilenameInformation,
            sectionInformation.UnManagedPtr.ToUIntPtr(),
            (ulong)Marshal.SizeOf<Win32.SectionInfo>(),
            ref length);

        // 32bit game
        if (!Is64Bit)
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

        List<string> drivesLetter = DriveInfo.GetDrives().Select(d => d.Name.Replace("\\", "")).ToList();
        foreach (string driveLetter in drivesLetter)
        {
            var sb = new StringBuilder(64);
            _ = Win32.QueryDosDevice(driveLetter, sb, 64 * 2); // * 2 Unicode

            if (deviceName.Contains(sb.ToString()))
                return true;
        }

        return false;
    }

    public override void Dispose()
    {
        GC.SuppressFinalize(this);
        Clean();
    }
}