using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace MochaGuard
{
    internal static class MemoryGuard
    {
        private static IntPtr _gameAssemblyBase;
        private static uint _gameAssemblySize;
        private static readonly List<(IntPtr Addr, byte[] Original, string Name)> _watched = new List<(IntPtr, byte[], string)>();
        private static bool _initialized;

        public static bool Init()
        {
            try
            {
                IntPtr hMod = Native.GetModuleHandleW("GameAssembly.dll");
                if (hMod == IntPtr.Zero)
                {
                    Punisher.LogWarn("MemoryGuard: GameAssembly.dll not found");
                    return false;
                }

                if (!Native.GetModuleInformation(Native.GetCurrentProcess(), hMod, out Native.MODULEINFO info, (uint)Marshal.SizeOf<Native.MODULEINFO>()))
                {
                    Punisher.LogWarn("MemoryGuard: GetModuleInformation failed");
                    return false;
                }

                _gameAssemblyBase = info.lpBaseOfDll;
                _gameAssemblySize = info.SizeOfImage;
                Punisher.Log($"MemoryGuard: GameAssembly.dll base=0x{_gameAssemblyBase.ToInt64():X} size=0x{_gameAssemblySize:X}");

                _watched.Clear();

                IntPtr[] exportScan = new IntPtr[] { hMod };
                WatchExportPrologue(hMod, "il2cpp_init");
                WatchExportPrologue(hMod, "il2cpp_runtime_init");
                WatchExportPrologue(hMod, "il2cpp_class_get_methods");
                WatchExportPrologue(hMod, "il2cpp_resolve_icall");
                WatchExportPrologue(hMod, "il2cpp_runtime_invoke");

                _initialized = _watched.Count > 0;
                if (_initialized)
                    Punisher.Log($"MemoryGuard: watching {_watched.Count} GameAssembly exports");
                else
                    Punisher.LogWarn("MemoryGuard: no exports could be watched");

                return _initialized;
            }
            catch (Exception ex) { Punisher.LogWarn("MemoryGuard.Init ex: " + ex.Message); return false; }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        private static void WatchExportPrologue(IntPtr hMod, string exportName)
        {
            try
            {
                IntPtr addr = GetProcAddress(hMod, exportName);
                if (addr == IntPtr.Zero)
                    return;

                byte[] orig = new byte[32];
                if (Native.ReadProcessMemory(Native.GetCurrentProcess(), addr, orig, (IntPtr)orig.Length, out _))
                {
                    _watched.Add((addr, orig, exportName));
                    Punisher.Log($"MemoryGuard: watching {exportName} @ 0x{addr.ToInt64():X}");
                }
            }
            catch { }
        }

        public static void Verify()
        {
            if (!_initialized)
                return;

            try
            {
                foreach (var w in _watched)
                {
                    byte[] cur = new byte[w.Original.Length];
                    if (!Native.ReadProcessMemory(Native.GetCurrentProcess(), w.Addr, cur, (IntPtr)cur.Length, out _))
                        continue;

                    bool diff = false;
                    for (int i = 0; i < cur.Length; i++)
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
                        Punisher.LogWarn($"MemoryGuard: MISMATCH on {w.Name} old=[{oldHex}] new=[{newHex}]");
                        Punisher.Kill($"mem:{w.Name}");
                    }
                }
            }
            catch (Exception ex) { Punisher.LogWarn("MemoryGuard.Verify ex: " + ex.Message); }
        }
    }
}
