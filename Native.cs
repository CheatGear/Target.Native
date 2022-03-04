using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using CG.Framework.Attributes;
using CG.Framework.Plugin.Memory;

namespace CG.Memory;

[PluginInfo("CorrM", "Native", "Use current system API to read/write memory process", "https://github.com/CheatGear", "https://github.com/CheatGear/Memory.Native")]
public class Native : MemoryPlugin
{
    private MemoryInitInfo _initInfo;
    private IntPtr _pHandle;
    private Win32.SystemInfo _sysInfo;
    private int _memoryBasicInformationSize;

    public override Version TargetFrameworkVersion { get; } = new(3, 0, 0);
    public override Version PluginVersion { get; } = new(3, 0, 0);
    public override bool Is64Bit { get; protected set; }

    private static bool Is64BitProcess(IntPtr processHandle)
    {
        return Win32.IsWow64Process(processHandle, out bool retVal) && !retVal;
    }

    private UIntPtr GameStartAddress()
    {
        return _sysInfo.MinimumApplicationAddress;
    }

    private UIntPtr GameEndAddress()
    {
        return _sysInfo.MaximumApplicationAddress;
    }

    protected override bool OnInit(MemoryInitInfo info)
    {
        _initInfo = info;

        _pHandle = Win32.OpenProcess(Win32.ProcessAccessFlags.All, false, info.Process.Id);
        Is64Bit = Is64BitProcess(_pHandle);

        _memoryBasicInformationSize = Marshal.SizeOf<Win32.MemoryBasicInformation>();
        Win32.GetSystemInfo(out _sysInfo);

        return true;
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

            buffer = bytes[0..numberOfBytesRead];
            bool allRead = numberOfBytesRead == size && buffer.Length > 0;
            numberOfBytesRead = cSize;
            return allRead;
        }
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

    public override List<MemoryModuleInfo> GetModuleList()
    {
        var ret = new List<MemoryModuleInfo>();
        // To Avoid Some Games not share it's modules, or could be emulator game
        try
        {
            IntPtr hSnap = Win32.CreateToolhelp32Snapshot(Win32.SnapshotFlags.Module | Win32.SnapshotFlags.Module32, _initInfo.Process.Id);
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
                        ret.Add(modEntry);
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

    public override bool IsValidRemoteAddress(UIntPtr address)
    {
        // TODO: Very bad when called in hot-path
        if (address == UIntPtr.Zero || IsBadAddress(address))
            return false;

        if (Win32.VirtualQueryEx(_pHandle, address, out Win32.MemoryBasicInformation info, (uint)_memoryBasicInformationSize) != 0)
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

    public override void Dispose()
    {
        base.Dispose();

        Win32.CloseHandle(_pHandle);
        GC.SuppressFinalize(this);
    }
}