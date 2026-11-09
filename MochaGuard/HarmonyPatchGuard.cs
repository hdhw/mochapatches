using System;
using System.Collections.Generic;
using System.Reflection;
using HarmonyLib;

namespace MochaGuard
{
    internal static class HarmonyPatchGuard
    {
        // Matched as substrings against a patch's Harmony owner id (see CheckPatches).
        // AllowHost adds the id MochaPatches' own patches are applied under at runtime,
        // so the merged build does not detect itself.
        private static readonly HashSet<string> _allowedOwners = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "mochaguard",
            "mocha",
            "0woofpatch",
            "woofpatch",
            // Framework owners. MelonLoader and Il2CppInterop legitimately Harmony-patch
            // core methods (e.g. MelonLoader patches Assembly.Load) in every modded
            // session; without these the guard kills the game over the loader's own
            // patches. Confirmed KILL on Assembly.Load by MelonLoader on a live launch.
            "melonloader",
            "il2cppinterop",
            "harmony",
        };

        private static readonly object _ownerLock = new object();

        /// <summary>
        /// Registers the hosting MelonMod's Harmony instance id (and its assembly name)
        /// as allowed patch owners. MelonLoader applies a melon's [HarmonyPatch] classes
        /// under that instance, so without this every MochaPatches patch reads as foreign
        /// and the first HarmonyLoop scan would kill the game. Called from
        /// GuardRuntime.Start before any watchdog thread is running.
        /// </summary>
        public static void AllowHost(MelonLoader.MelonMod host)
        {
            if (host == null)
                return;

            try
            {
                HarmonyLib.Harmony harmony = host.HarmonyInstance;
                if (harmony != null)
                    AllowOwner(harmony.Id);
            }
            catch (Exception ex) { Punisher.LogWarn("HarmonyPatchGuard.AllowHost harmony ex: " + ex.Message); }

            try
            {
                AllowOwner(host.GetType().Assembly.GetName().Name);
            }
            catch (Exception ex) { Punisher.LogWarn("HarmonyPatchGuard.AllowHost asm ex: " + ex.Message); }
        }

        public static void AllowOwner(string owner)
        {
            if (string.IsNullOrEmpty(owner))
                return;

            lock (_ownerLock)
            {
                if (_allowedOwners.Add(owner))
                    Punisher.Log($"HarmonyPatchGuard: allowed owner '{owner}'");
            }
        }

        private static readonly string[] _criticalMethodNames = new string[]
        {
            "Exit", "FailFast", "Terminate",
            "OnInitializeMelon", "OnDeinitializeMelon",
            "OnUpdate", "OnFixedUpdate", "OnGUI",
        };

        public static void Scan()
        {
            try
            {
                var patchedMethods = HarmonyLib.Harmony.GetAllPatchedMethods();
                if (patchedMethods == null)
                    return;

                foreach (MethodBase mb in patchedMethods)
                {
                    if (mb == null)
                        continue;

                    try
                    {
                        var patches = HarmonyLib.Harmony.GetPatchInfo(mb);
                        if (patches == null)
                            continue;

                        string foreignOwner = CheckPatches(patches.Prefixes);
                        if (foreignOwner == null)
                            foreignOwner = CheckPatches(patches.Postfixes);
                        if (foreignOwner == null)
                            foreignOwner = CheckPatches(patches.Transpilers);
                        if (foreignOwner == null)
                            foreignOwner = CheckPatches(patches.Finalizers);

                        if (foreignOwner != null)
                        {
                            string methodDesc = $"{mb.DeclaringType?.Name}.{mb.Name}";
                            bool isCritical = false;
                            foreach (var cn in _criticalMethodNames)
                            {
                                if (mb.Name.IndexOf(cn, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    isCritical = true;
                                    break;
                                }
                            }

                            if (mb.DeclaringType == typeof(Environment))
                                isCritical = true;

                            Punisher.LogWarn($"HarmonyPatchGuard: foreign patch on {methodDesc} by {foreignOwner} critical={isCritical}");
                            if (isCritical)
                            {
                                // A foreign patch on a critical method (process exit, the
                                // melon lifecycle, Environment.*) is an attempt to defeat
                                // the guard itself: high confidence, kill.
                                Punisher.Kill($"hpatch:{methodDesc} by={foreignOwner}");
                                return;
                            }

                            // A foreign patch on an ordinary method is just another mod
                            // touching the game (common and usually harmless). Report it
                            // and keep scanning rather than killing honest players.
                            Punisher.Report($"hpatch:{methodDesc} by={foreignOwner}");
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) { Punisher.LogWarn("HarmonyPatchGuard.Scan ex: " + ex.Message); }
        }

        private static string CheckPatches(IEnumerable<Patch> patches)
        {
            if (patches == null)
                return null;

            foreach (var p in patches)
            {
                if (p == null)
                    continue;

                string owner = p.owner;
                if (string.IsNullOrEmpty(owner))
                    continue;

                bool allowed = false;
                lock (_ownerLock)
                {
                    foreach (var a in _allowedOwners)
                    {
                        if (owner.IndexOf(a, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            allowed = true;
                            break;
                        }
                    }
                }

                if (!allowed)
                    return owner;
            }

            return null;
        }

        public static void CheckEnvironmentExit()
        {
            try
            {
                // Environment.Exit takes an int (exit code), not a string. Looking it
                // up as Exit(string) returned null, so this check never actually ran.
                var exitMethod = typeof(Environment).GetMethod("Exit", BindingFlags.Static | BindingFlags.Public, null, new Type[] { typeof(int) }, null);
                if (exitMethod != null)
                {
                    var patches = HarmonyLib.Harmony.GetPatchInfo(exitMethod);
                    if (patches != null)
                    {
                        string foreignOwner = CheckPatches(patches.Prefixes);
                        if (foreignOwner == null)
                            foreignOwner = CheckPatches(patches.Postfixes);
                        if (foreignOwner == null)
                            foreignOwner = CheckPatches(patches.Transpilers);
                        if (foreignOwner == null)
                            foreignOwner = CheckPatches(patches.Finalizers);

                        if (foreignOwner != null)
                        {
                            Punisher.LogWarn($"HarmonyPatchGuard: Environment.Exit patched by {foreignOwner}");
                            Punisher.Kill($"envexit:{foreignOwner}");
                        }
                    }
                }

                // FailFast has two overloads (string) and (string, Exception); asking by
                // name alone threw AmbiguousMatchException ("Ambiguous match found") every
                // scan. Pin the (string) overload explicitly.
                var failFastMethod = typeof(Environment).GetMethod("FailFast", BindingFlags.Static | BindingFlags.Public, null, new Type[] { typeof(string) }, null);
                if (failFastMethod != null)
                {
                    var patches = HarmonyLib.Harmony.GetPatchInfo(failFastMethod);
                    if (patches != null)
                    {
                        string foreignOwner = CheckPatches(patches.Prefixes);
                        if (foreignOwner == null)
                            foreignOwner = CheckPatches(patches.Postfixes);
                        if (foreignOwner == null)
                            foreignOwner = CheckPatches(patches.Transpilers);
                        if (foreignOwner == null)
                            foreignOwner = CheckPatches(patches.Finalizers);

                        if (foreignOwner != null)
                        {
                            Punisher.LogWarn($"HarmonyPatchGuard: Environment.FailFast patched by {foreignOwner}");
                            Punisher.Kill($"envfailfast:{foreignOwner}");
                        }
                    }
                }
            }
            catch (Exception ex) { Punisher.LogWarn("HarmonyPatchGuard.CheckEnvironmentExit ex: " + ex.Message); }
        }
    }
}
