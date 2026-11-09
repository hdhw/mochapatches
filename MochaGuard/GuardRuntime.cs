using System;
using System.Threading;
using MelonLoader;

namespace MochaGuard
{
    /// <summary>
    /// MochaGuard's lifecycle controller.
    ///
    /// This was a standalone MelonMod (MochaGuardMod). MochaGuard now ships inside
    /// MochaPatches.dll, and an assembly may only carry one [MelonInfo], so the mod
    /// entry point became a static runtime that MochaPatches' Core drives:
    /// Core.OnInitializeMelon -> Start(host), Core.OnDeinitializeMelon -> Stop().
    /// The watchdog set, its start order and every interval are unchanged.
    /// </summary>
    internal static class GuardRuntime
    {
        internal const string GuardVersion = "1.0.0";

        private static bool _started;
        private static Thread _moduleThread;
        private static Thread _memoryThread;
        private static Thread _externalThread;
        private static Thread _hookThread;
        private static Thread _fileThread;
        private static Thread _ceThread;
        private static Thread _harmonyThread;
        private static Thread _il2cppThread;
        private static volatile bool _running = true;

        /// <summary>
        /// Starts every watchdog. <paramref name="host"/> is the MelonMod that MochaGuard
        /// now lives inside; its Harmony instance id is registered as an allowed patch
        /// owner so HarmonyPatchGuard does not kill the game over MochaPatches' own
        /// patches, which are applied under that id.
        /// </summary>
        public static void Start(MelonMod host)
        {
            if (_started)
                return;
            _started = true;
            _running = true;

            try
            {
                HarmonyPatchGuard.AllowHost(host);

                string gameDir = System.AppContext.BaseDirectory;
                if (string.IsNullOrEmpty(gameDir))
                {
                    try { gameDir = System.Environment.CurrentDirectory; } catch { }
                }
                if (string.IsNullOrEmpty(gameDir))
                {
                    try
                    {
                        string exe = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                        gameDir = System.IO.Path.GetDirectoryName(exe);
                    } catch { }
                }
                if (string.IsNullOrEmpty(gameDir))
                {
                    try { gameDir = System.IO.Directory.GetCurrentDirectory(); } catch { }
                }
                if (!gameDir.EndsWith("\\") && !gameDir.EndsWith("/"))
                    gameDir += "\\";

                Blacklist.SetGameDir(gameDir);
                FileScanner.Init(gameDir);
                Punisher.SetLogPath(System.IO.Path.Combine(gameDir, "MochaGuard.log"));
                Punisher.Log("=== MochaGuard " + GuardVersion + " starting (hosted by MochaPatches " + Mocha.Patch.Core.ModVersion + ") ===");
                Punisher.Log($"GameDir: {gameDir}");
                Punisher.Log($"AppContext.BaseDirectory: '{System.AppContext.BaseDirectory}'");
                Punisher.Log($"Environment.CurrentDirectory: '{System.Environment.CurrentDirectory}'");
                Punisher.Log($"Self PID: {Native.GetCurrentProcessId()}");

                ExternalGuard.Start();
                ModuleGuard.Start();

                _moduleThread = new Thread(ModuleLoop) { IsBackground = true, Name = "mg-m" };
                _memoryThread = new Thread(MemoryLoop) { IsBackground = true, Name = "mg-i" };
                _externalThread = new Thread(ExternalLoop) { IsBackground = true, Name = "mg-e" };
                _hookThread = new Thread(HookLoop) { IsBackground = true, Name = "mg-h" };
                _fileThread = new Thread(FileLoop) { IsBackground = true, Name = "mg-f" };
                _ceThread = new Thread(CELoop) { IsBackground = true, Name = "mg-c" };
                _harmonyThread = new Thread(HarmonyLoop) { IsBackground = true, Name = "mg-hp" };
                _il2cppThread = new Thread(Il2CppLoop) { IsBackground = true, Name = "mg-il" };

                _moduleThread.Start();
                _memoryThread.Start();
                _externalThread.Start();
                _hookThread.Start();
                _fileThread.Start();
                _ceThread.Start();
                _harmonyThread.Start();
                _il2cppThread.Start();

                MelonLogger.Msg("MochaGuard active");
                Punisher.Log("All watchdog threads started");
            }
            catch (Exception ex)
            {
                MelonLogger.Error("MG init: " + ex);
                try { Punisher.LogWarn("OnInitializeMelon FATAL: " + ex); } catch { }
            }
        }

        public static void Stop()
        {
            _running = false;
        }

        private static void ModuleLoop()
        {
            Punisher.Log("ModuleLoop started");
            while (_running)
            {
                try { ModuleGuard.Scan(); } catch (Exception ex) { Punisher.LogWarn("ModuleLoop ex: " + ex.Message); }
                Thread.Sleep(750);
            }
        }

        private static void MemoryLoop()
        {
            Punisher.Log("MemoryLoop started, waiting 15s before init");
            Thread.Sleep(15000);
            try
            {
                if (!MemoryGuard.Init())
                {
                    Punisher.LogWarn("MemoryGuard.Init failed first attempt, retrying in 10s");
                    Thread.Sleep(10000);
                    MemoryGuard.Init();
                }
            }
            catch (Exception ex) { Punisher.LogWarn("MemoryLoop init ex: " + ex.Message); }

            Thread.Sleep(5000);
            Punisher.Log("MemoryLoop verification started");
            while (_running)
            {
                try { MemoryGuard.Verify(); } catch (Exception ex) { Punisher.LogWarn("MemoryLoop verify ex: " + ex.Message); }
                Thread.Sleep(2000);
            }
        }

        private static void ExternalLoop()
        {
            Punisher.Log("ExternalLoop started, waiting 5s");
            Thread.Sleep(5000);
            while (_running)
            {
                try { ExternalGuard.ScanProcesses(); } catch (Exception ex) { Punisher.LogWarn("ExternalLoop proc ex: " + ex.Message); }
                Thread.Sleep(2000);
                try { ExternalGuard.ScanWindows(); } catch (Exception ex) { Punisher.LogWarn("ExternalLoop wnd ex: " + ex.Message); }
                Thread.Sleep(3000);
            }
        }

        private static void HookLoop()
        {
            Punisher.Log("HookLoop started, waiting 15s before snapshot");
            Thread.Sleep(15000);
            try { HookGuard.SnapshotPrologues(); } catch (Exception ex) { Punisher.LogWarn("HookLoop snapshot ex: " + ex.Message); }
            Thread.Sleep(5000);
            Punisher.Log("HookLoop verification started");
            while (_running)
            {
                try { HookGuard.VerifyPrologues(); } catch (Exception ex) { Punisher.LogWarn("HookLoop verify ex: " + ex.Message); }
                Thread.Sleep(1000);
            }
        }

        private static void FileLoop()
        {
            Punisher.Log("FileLoop started, waiting 10s");
            Thread.Sleep(10000);
            while (_running)
            {
                try { FileScanner.Scan(); } catch (Exception ex) { Punisher.LogWarn("FileLoop ex: " + ex.Message); }
                Thread.Sleep(30000);
            }
        }

        private static void CELoop()
        {
            Punisher.Log("CELoop started, waiting 5s");
            Thread.Sleep(5000);
            while (_running)
            {
                try { ExternalGuard.ScanCheatEngine(); } catch (Exception ex) { Punisher.LogWarn("CELoop ce ex: " + ex.Message); }
                Thread.Sleep(500);
                try { ExternalGuard.ScanHttpDebugger(); } catch (Exception ex) { Punisher.LogWarn("CELoop hd ex: " + ex.Message); }
                Thread.Sleep(500);
            }
        }

        private static void HarmonyLoop()
        {
            Punisher.Log("HarmonyLoop started, waiting 20s");
            Thread.Sleep(20000);
            while (_running)
            {
                try { HarmonyPatchGuard.Scan(); } catch (Exception ex) { Punisher.LogWarn("HarmonyLoop scan ex: " + ex.Message); }
                Thread.Sleep(1000);
                try { HarmonyPatchGuard.CheckEnvironmentExit(); } catch (Exception ex) { Punisher.LogWarn("HarmonyLoop env ex: " + ex.Message); }
                Thread.Sleep(4000);
            }
        }

        private static void Il2CppLoop()
        {
            Punisher.Log("Il2CppLoop started, waiting 20s before init");
            Thread.Sleep(20000);
            try { Il2CppGuard.Init(); } catch (Exception ex) { Punisher.LogWarn("Il2CppLoop init ex: " + ex.Message); }
            Thread.Sleep(5000);
            Punisher.Log("Il2CppLoop verification started");
            while (_running)
            {
                try { Il2CppGuard.Verify(); } catch (Exception ex) { Punisher.LogWarn("Il2CppLoop verify ex: " + ex.Message); }
                Thread.Sleep(2000);
            }
        }
    }
}
