using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace MochaGuard
{
    internal static class HookGuard
    {
        private static readonly List<(IntPtr Addr, byte[] Original, string Name)> _watched = new List<(IntPtr, byte[], string)>();
        private static bool _initialized;

        private static readonly string[] _watchedApis = new string[]
        {
            "ntdll.dll", "NtOpenProcess",
            "ntdll.dll", "NtReadVirtualMemory",
            "ntdll.dll", "NtWriteVirtualMemory",
            "ntdll.dll", "NtQueryVirtualMemory",
            "ntdll.dll", "NtProtectVirtualMemory",
            "ntdll.dll", "NtCreateThreadEx",
            "ntdll.dll", "LdrLoadDll",
            "ntdll.dll", "LdrRegisterDllNotification",
            "kernel32.dll", "OpenProcess",
            "kernel32.dll", "WriteProcessMemory",
            "kernel32.dll", "ReadProcessMemory",
            "kernel32.dll", "CreateRemoteThread",
            "kernel32.dll", "VirtualProtectEx",
            "kernel32.dll", "LoadLibraryW",
            "kernel32.dll", "LoadLibraryA",
            "kernel32.dll", "LoadLibraryExW",
            "kernelbase.dll", "OpenProcess",
            "kernelbase.dll", "WriteProcessMemory",
            "kernelbase.dll", "ReadProcessMemory",
            "kernelbase.dll", "CreateRemoteThread",
            "kernelbase.dll", "VirtualProtectEx",
        };

        public static void SnapshotPrologues()
        {
            try
            {
                _watched.Clear();

                for (int i = 0; i < _watchedApis.Length; i += 2)
                {
                    string dll = _watchedApis[i];
                    string api = _watchedApis[i + 1];

                    try
                    {
                        IntPtr hMod = Native.GetModuleHandleW(dll);
                        if (hMod == IntPtr.Zero)
                            continue;

                        IntPtr proc = Native.OpenProcess(Native.PROCESS_QUERY_INFORMATION | Native.PROCESS_VM_READ, false, Native.GetCurrentProcessId());
                        try
                        {
                            var sb = new System.Text.StringBuilder(256);
                            uint len = Native.GetModuleFileNameW(hMod, sb, (uint)sb.Capacity);
                            string path = len > 0 ? sb.ToString() : dll;

                            IntPtr addr = GetProcAddress(hMod, api);
                            if (addr == IntPtr.Zero)
                                continue;

                            byte[] orig = new byte[16];
                            if (Native.ReadProcessMemory(Native.GetCurrentProcess(), addr, orig, (IntPtr)orig.Length, out _))
                            {
                                _watched.Add((addr, orig, $"{dll}!{api}"));
                                Punisher.Log($"HookGuard: watching {dll}!{api} @ 0x{addr.ToInt64():X}");
                            }
                        }
                        finally
                        {
                            if (proc != IntPtr.Zero)
                                Native.CloseHandle(proc);
                        }
                    }
                    catch { }
                }

                _initialized = _watched.Count > 0;
                Punisher.Log($"HookGuard: snapshot complete, {_watched.Count} APIs watched");
            }
            catch (Exception ex) { Punisher.LogWarn("HookGuard.SnapshotPrologues ex: " + ex.Message); }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        public static void VerifyPrologues()
        {
            if (!_initialized)
                return;

            try
            {
                foreach (var w in _watched)
                {
                    byte[] cur = new byte[16];
                    if (!Native.ReadProcessMemory(Native.GetCurrentProcess(), w.Addr, cur, (IntPtr)cur.Length, out _))
                        continue;

                    bool diff = false;
                    for (int i = 0; i < 16; i++)
                    {
                        if (cur[i] != w.Original[i])
                        {
                            diff = true;
                            break;
                        }
                    }

                    if (diff)
                    {
                        string oldHex = BitConverter.ToString(w.Original).Replace("-", " ");
                        string newHex = BitConverter.ToString(cur).Replace("-", " ");
                        // Report-only. Legitimate software hooks these same ntdll/kernel32
                        // entry points on real machines: Steam/Discord/GPU overlays, OBS
                        // and other capture tools, RivaTuner/Afterburner, some antivirus.
                        // Killing here crashed honest players, so this is telemetry now.
                        Punisher.Report($"hook:{w.Name} old=[{oldHex}] new=[{newHex}]");
                    }
                }
            }
            catch (Exception ex) { Punisher.LogWarn("HookGuard.VerifyPrologues ex: " + ex.Message); }
        }
    }
}
