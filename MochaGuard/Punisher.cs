using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace MochaGuard
{
    internal static class Punisher
    {
        private static string _logPath;
        private static readonly object _lock = new object();
        private static volatile bool _killed;

        public static void SetLogPath(string path)
        {
            _logPath = path;
        }

        public static void Log(string msg)
        {
            try
            {
                lock (_lock)
                {
                    string line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
                    MelonLoader.MelonLogger.Msg(line);
                    if (!string.IsNullOrEmpty(_logPath))
                        File.AppendAllText(_logPath, line + Environment.NewLine);
                }
            }
            catch { }
        }

        public static void LogWarn(string msg)
        {
            try
            {
                lock (_lock)
                {
                    string line = $"[{DateTime.Now:HH:mm:ss.fff}] WARN: {msg}";
                    MelonLoader.MelonLogger.Warning(line);
                    if (!string.IsNullOrEmpty(_logPath))
                        File.AppendAllText(_logPath, line + Environment.NewLine);
                }
            }
            catch { }
        }

        // Report-only detection. Records a signal WITHOUT killing the process. Used for
        // heuristics that false-positive on legitimate software (overlay/capture hooks,
        // unrecognized-but-unnamed modules). The line is greppable in MochaGuard.log and
        // is the hook point for server-side telemetry later.
        public static void Report(string reason)
        {
            LogWarn($"DETECT (report-only): {reason}");
            try
            {
                if (!string.IsNullOrEmpty(_logPath))
                    File.AppendAllText(_logPath, $"[{DateTime.Now:HH:mm:ss.fff}] DETECT: {reason}{Environment.NewLine}");
            }
            catch { }
        }

        public static void Kill(string reason)
        {
            LogWarn($"KILL TRIGGERED: {reason}");

            // Dev-only kill switch. Compiled in ONLY for MOCHA_DEV builds, so the
            // shipped (release) DLL has no local bypass to discover - deobfuscating
            // it, or reading the log, reveals nothing because the code path is not
            // present. The suppression message deliberately does not name any file.
#if MOCHA_DEV
            if (IsDisarmed())
            {
                LogWarn("KILL SUPPRESSED (dev build): " + reason);
                return;
            }
#endif

            try { File.AppendAllText(_logPath ?? "MochaGuard.log", $"[{DateTime.Now:HH:mm:ss.fff}] KILL: {reason}{Environment.NewLine}"); } catch { }

            if (_killed)
                return;
            _killed = true;

            try { Thread.Sleep(200); } catch { }

            try
            {
                Environment.FailFast($"MochaGuard: {reason}");
            }
            catch { }

            try
            {
                Process.GetCurrentProcess().Kill();
            }
            catch { }

            try
            {
                Native.TerminateProcess(Native.GetCurrentProcess(), 1);
            }
            catch { }
        }

#if MOCHA_DEV
        private static bool IsDisarmed()
        {
            try
            {
                string dir = string.IsNullOrEmpty(_logPath)
                    ? System.IO.Directory.GetCurrentDirectory()
                    : Path.GetDirectoryName(_logPath);
                if (string.IsNullOrEmpty(dir))
                    return false;
                return File.Exists(Path.Combine(dir, "mochaguard_off.txt"));
            }
            catch { return false; }
        }
#endif
    }
}
