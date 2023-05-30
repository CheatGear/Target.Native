using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using CG.SDK.Dotnet.Attributes;
using CG.SDK.Dotnet.Helper;
using CG.SDK.Dotnet.Helper.Platform;
using CG.SDK.Dotnet.Plugin.Target;

namespace CG.Memory;

[PluginInfo(Name = nameof(Native), Version = "5.0.0", Author = "CorrM", Description = "Use current system API to read/write memory process", WebsiteLink = "https://github.com/CheatGear", SourceCodeLink = "https://github.com/CheatGear/Memory.Native")]
public sealed class Native : TargetHandlerPlugin<Win32MemoryHandler>
{
    private readonly int _memoryBasicInformationSize;
    private readonly Win32.SystemInfo _sysInfo;
    private nint _processHandle;
    private nuint? _minValidAddress;
    private nuint? _maxValidAddress;

    public override Win32MemoryHandler MemoryHandler { get; }

    public Native()
    {
        _memoryBasicInformationSize = Marshal.SizeOf<Win32.MemoryBasicInformation>();
        Win32.GetSystemInfo(out _sysInfo);

        MemoryHandler = new Win32MemoryHandler(this);
    }

    private static bool IsValidHandle(nint handle)
    {
        return handle != nint.Zero && handle != Win32.InvalidHandleValue;
    }

    private void AssertTarget()
    {
        if (IsValidHandle(_processHandle))
            return;

        throw new Exception("No target");
    }

    protected override void OnTargetFree()
    {
        _minValidAddress = null;
        _maxValidAddress = null;

        MemoryHandler.OnTargetFree();

        try
        {
            // Suspend games case an Exception
            if (IsValidHandle(_processHandle))
                Win32.CloseHandle(_processHandle);
        }
        catch (Exception)
        {
            // ignored
        }
    }

    protected override bool OnTargetLock(int processId)
    {
        _processHandle = Win32.OpenProcess(Win32.ProcessAccessFlags.All, false, processId);

        return IsValidHandle(_processHandle);
    }

    protected override void OnTargetReady()
    {
        _minValidAddress = GetMinValidAddress();
        _maxValidAddress = GetMaxValidAddress();

        MemoryHandler.OnTargetReady(_processHandle);
    }

    protected override IReadOnlyList<MemModuleInfo> GetModules()
    {
        AssertTarget();

        var ret = new List<MemModuleInfo>();

        int capacity = 1024;
        var sb = new StringBuilder(capacity);
        Win32.QueryFullProcessImageName(_processHandle, 0, sb, ref capacity);
        string fullPath = sb.ToString(0, capacity);

        // To Avoid Some Games not share it's modules, or could be emulator/protected game
        nint hSnap = Win32.CreateToolhelp32Snapshot(Win32.SnapshotFlags.Module | Win32.SnapshotFlags.Module32, ProcessId);
        if (!IsValidHandle(hSnap))
            return ret;

        try
        {
            var modEntry = new Win32.ModuleEntry32()
            {
                DwSize = (uint)Marshal.SizeOf(typeof(Win32.ModuleEntry32))
            };

            if (Win32.Module32First(hSnap, ref modEntry))
            {
                do
                {
                    var mod = new MemModuleInfo()
                    {
                        Handle = modEntry.HModule,
                        Address = modEntry.ModBaseAddr.ToUIntPtr(),
                        Size = modEntry.ModBaseSize,
                        Name = modEntry.SzModule,
                        Path = modEntry.SzExePath,
                        MainModule = modEntry.SzExePath == fullPath
                    };
                    ret.Add(mod);
                } while (Win32.Module32Next(hSnap, ref modEntry));
            }
        }
        catch
        {
            // Ignore
        }

        Win32.CloseHandle(hSnap);

        return ret;
    }

    protected override bool GetIs64Bit()
    {
        AssertTarget();
        return UtilsExtensions.Is64BitProcess(_processHandle);
    }

    protected override int GetSystemPageSize()
    {
        return (int)_sysInfo.PageSize;
    }

    public override nuint GetMinValidAddress()
    {
        AssertTarget();
        return _minValidAddress ?? _sysInfo.MinimumApplicationAddress;
    }

    public override nuint GetMaxValidAddress()
    {
        AssertTarget();

        if (_maxValidAddress is not null)
            return _maxValidAddress.Value;

        return (nuint)(_sysInfo.ProcessorArchitecture == Win32.ProcessorArchitecture.X64 && Process64Bit ? 0x800000000000 : 0x100000000);
    }

    public override MemRegionInfo? GetMemoryRegion(nuint address)
    {
        AssertTarget();

        // Get Region information
        bool valid = Win32.VirtualQueryEx(
            _processHandle,
            address,
            out Win32.MemoryBasicInformation info,
            (uint)_memoryBasicInformationSize
        ) == _memoryBasicInformationSize;

        if (!valid)
            return null;

        var region = new MemRegionInfo()
        {
            AllocationBase = info.AllocationBase,
            BaseAddress = info.BaseAddress,
            Size = info.RegionSize.ToNum(),
            State = (uint)info.State,
            Protect = (uint)info.Protect,
            Type = (uint)info.Type
        };

        return region;
    }

    public override bool IsValidRegion(MemRegionInfo memRegion)
    {
        AssertTarget();

        bool check = ((Win32.MemoryState)memRegion.State & Win32.MemoryState.MemCommit) != 0;
        if (!check)
            return false;

        check = ((Win32.MemoryProtection)memRegion.Protect & Win32.MemoryProtection.PageNoAccess) == 0
                && ((Win32.MemoryProtection)memRegion.Protect & Win32.MemoryProtection.PageTargetsInvalid) == 0
                && ((Win32.MemoryProtection)memRegion.Protect & Win32.MemoryProtection.PageGuard) == 0
                && ((Win32.MemoryProtection)memRegion.Protect & Win32.MemoryProtection.PageNocache) == 0;

        return check;
    }

    public override bool IsValidProcess(int processId)
    {
        try
        {
            Process.GetProcessById(processId).Dispose();
        }
        catch
        {
            return false;
        }

        return true;
    }

    public override bool IsValidTarget()
    {
        return IsValidProcess(ProcessId) && IsValidHandle(_processHandle);
    }

    public override bool Suspend()
    {
        AssertTarget();

        return Win32.NtSuspendProcess(_processHandle) >= 0;
    }

    public override bool Resume()
    {
        AssertTarget();

        return Win32.NtResumeProcess(_processHandle) >= 0;
    }

    public override bool Terminate()
    {
        AssertTarget();

        return Win32.NtTerminateProcess(_processHandle, 0) >= 0;
    }
}
