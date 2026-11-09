using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

namespace MochaGuard
{
    internal static class Il2CppGuard
    {
        private static readonly List<(IntPtr Addr, byte[] Original, string Name)> _watched = new List<(IntPtr, byte[], string)>();
        private static bool _initialized;

        public static void Init()
        {
            try
            {
                _watched.Clear();

                var targets = new[]
                {
                    new { Type = "RecRoom.Core.Locomotion.PlayerMovement", Method = "Move", Params = 0 },
                    new { Type = "RecRoom.Core.Combat.RangedWeapon", Method = "Fire", Params = 0 },
                    new { Type = "RecRoom.Core.Player", Method = "Update", Params = 0 },
                    new { Type = "UnityEngine.Camera", Method = "set_fieldOfView", Params = 1 },
                };

                foreach (var t in targets)
                {
                    try
                    {
                        IntPtr addr = TryGetMethodPointer(t.Type, t.Method, t.Params);
                        if (addr != IntPtr.Zero)
                        {
                            byte[] orig = new byte[16];
                            if (Native.ReadProcessMemory(Native.GetCurrentProcess(), addr, orig, (IntPtr)orig.Length, out _))
                            {
                                _watched.Add((addr, orig, $"{t.Type}.{t.Method}"));
                                Punisher.Log($"Il2CppGuard: watching {t.Type}.{t.Method} @ 0x{addr.ToInt64():X}");
                            }
                        }
                    }
                    catch { }
                }

                _initialized = _watched.Count > 0;
                if (_initialized)
                    Punisher.Log($"Il2CppGuard: initialized with {_watched.Count} watched methods");
                else
                    Punisher.LogWarn("Il2CppGuard: no methods could be watched (Il2CppInterop may not be available)");
            }
            catch (Exception ex) { Punisher.LogWarn("Il2CppGuard.Init ex: " + ex.Message); }
        }

        private static IntPtr TryGetMethodPointer(string typeName, string methodName, int paramCount)
        {
            try
            {
                foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
                {
                    Type type = null;
                    try { type = asm.GetType(typeName); } catch { }
                    if (type == null)
                        continue;

                    MethodInfo[] methods = type.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                    foreach (var mi in methods)
                    {
                        if (mi.Name != methodName || mi.GetParameters().Length != paramCount)
                            continue;

                        try
                        {
                            var field = type.GetField($"Il2CppMethodInfoPtrFieldFor{mi.Name}_{mi.GetParameters().Length}", BindingFlags.Static | BindingFlags.NonPublic);
                            if (field != null)
                            {
                                var ptrObj = field.GetValue(null);
                                if (ptrObj is IntPtr ptr && ptr != IntPtr.Zero)
                                {
                                    return ReadMethodPointerFromInfo(ptr);
                                }
                            }
                        }
                        catch { }

                        try
                        {
                            var il2cppInfoField = mi.DeclaringType.GetField("Il2CppMethodInfoPtr", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                            if (il2cppInfoField != null)
                            {
                                var ptrObj = il2cppInfoField.GetValue(null);
                                if (ptrObj is IntPtr ptr && ptr != IntPtr.Zero)
                                    return ReadMethodPointerFromInfo(ptr);
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return IntPtr.Zero;
        }

        private static IntPtr ReadMethodPointerFromInfo(IntPtr methodInfoPtr)
        {
            try
            {
                IntPtr methodPtr = Marshal.ReadIntPtr(methodInfoPtr);
                return methodPtr;
            }
            catch { return IntPtr.Zero; }
        }

        public static void Verify()
        {
            if (!_initialized || _watched.Count == 0)
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
                        Punisher.LogWarn($"Il2CppGuard: HOOK on {w.Name} @ 0x{w.Addr.ToInt64():X} old=[{oldHex}] new=[{newHex}]");
                        Punisher.Kill($"il2cpp:{w.Name}");
                    }
                }
            }
            catch (Exception ex) { Punisher.LogWarn("Il2CppGuard.Verify ex: " + ex.Message); }
        }
    }
}
