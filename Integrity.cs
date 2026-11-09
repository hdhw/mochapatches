using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Mocha.Patch
{
    internal enum InspectionResult
    {
        Clean,
        Detected,
        Inconclusive
    }


    internal enum DetectionReason
    {
        None,
        DebuggerAttached,
        UnexpectedModuleLoaded,
        UnrecognizedMelonPlugin,
        SuspiciousProcessObserved,
        ProcessEnumerationFailed,
        ModuleEnumerationFailed,
        MelonEnumerationFailed
    }
    internal readonly struct Signal
    {
        internal InspectionResult Result { get; }
        internal DetectionReason Reason { get; }
        internal string Detail { get; }
        internal bool Weak { get; }

        internal Signal(InspectionResult result, DetectionReason reason, string detail, bool weak)
        {
            Result = result;
            Reason = reason;
            Detail = detail;
            Weak = weak;
        }

        internal static Signal Clean(DetectionReason reason) =>
            new Signal(InspectionResult.Clean, reason, null, false);

        internal static Signal Inconclusive(DetectionReason reason, string detail) =>
            new Signal(InspectionResult.Inconclusive, reason, detail, false);

        internal static Signal Detected(DetectionReason reason, string detail, bool weak) =>
            new Signal(InspectionResult.Detected, reason, detail, weak);
    }

    internal sealed class IntegrityReport
    {
        internal List<Signal> Signals { get; } = new List<Signal>();

        internal int StrongDetectionCount =>
            Signals.Count(s => s.Result == InspectionResult.Detected && !s.Weak);

        internal bool AnyDetection => Signals.Any(s => s.Result == InspectionResult.Detected);
        internal bool AnyInconclusive => Signals.Any(s => s.Result == InspectionResult.Inconclusive);
        internal bool AllClean => Signals.All(s => s.Result == InspectionResult.Clean);

        internal string Describe()
        {
            if (Signals.Count == 0)
            {
                return "no-signals";
            }

            return string.Join(",", Signals
                .Where(s => s.Result != InspectionResult.Clean)
                .Select(s => $"{s.Reason}:{s.Result}{(s.Weak ? "(weak)" : "")}"
                    + (string.IsNullOrEmpty(s.Detail) ? "" : $"[{s.Detail}]")));
        }
    }

    internal static class KnownComponents
    {
        // Melon plugin name -> allowed versions ("*" = any version accepted).
        internal static readonly Dictionary<string, HashSet<string>> AllowedMelons =
            new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase)
            {
                ["MochaPatches"] = new HashSet<string> { "*" },
                ["MochaGuard"] = new HashSet<string> { "*" },
                ["Questifier"] = new HashSet<string> { "*" },
            };

        internal static bool IsAllowed(string name, string version)
        {
            if (!AllowedMelons.TryGetValue(name, out HashSet<string> versions))
            {
                return false;
            }

            return versions.Contains("*") || versions.Contains(version ?? "");
        }
    }

    internal static class Obf
    {
        private static readonly byte[] Key = { 0x4D, 0x63, 0x21, 0x9F, 0x0C, 0x7A, 0xE3, 0x18 };

        internal static string S(byte[] data)
        {
            byte[] outBytes = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                outBytes[i] = (byte)(data[i] ^ Key[i % Key.Length]);
            }
            return Encoding.UTF8.GetString(outBytes);
        }
    }

    internal static class Integrity
    {
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        private static readonly string[] WeakProcessSignatures =
        {
            Obf.S(new byte[] { 0x2E, 0x0B, 0x44, 0xFE, 0x78, 0x1F, 0x8D, 0x7F, 0x24, 0x0D, 0x44 }),          // cheatengine
            Obf.S(new byte[] { 0x35, 0x55, 0x15, 0xFB, 0x6E, 0x1D }),                                        // x64dbg
            Obf.S(new byte[] { 0x35, 0x50, 0x13, 0xFB, 0x6E, 0x1D }),                                        // x32dbg
            Obf.S(new byte[] { 0x22, 0x0F, 0x4D, 0xE6, 0x68, 0x18, 0x84 }),                                  // ollydbg
        };

        private static readonly HashSet<string> DeniedModuleFileNames =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                Obf.S(new byte[] { 0x28, 0x02, 0x52, 0xE6, 0x64, 0x15, 0x8C, 0x73, 0x63, 0x07, 0x4D, 0xF3 }),                     // easyhook.dll
                Obf.S(new byte[] { 0x28, 0x02, 0x52, 0xE6, 0x64, 0x15, 0x8C, 0x73, 0x7E, 0x51, 0x0F, 0xFB, 0x60, 0x16 }),         // easyhook32.dll
                Obf.S(new byte[] { 0x28, 0x02, 0x52, 0xE6, 0x64, 0x15, 0x8C, 0x73, 0x7B, 0x57, 0x0F, 0xFB, 0x60, 0x16 }),         // easyhook64.dll
                Obf.S(new byte[] { 0x3E, 0x0B, 0x40, 0xED, 0x7C, 0x17, 0x8C, 0x76, 0x22, 0x0A, 0x4F, 0xF5, 0x69, 0x19, 0x97, 0x77, 0x3F, 0x4D, 0x45, 0xF3, 0x60 }), // sharpmonoinjector.dll
                Obf.S(new byte[] { 0x3E, 0x13, 0x44, 0xFA, 0x68, 0x12, 0x82, 0x7B, 0x26, 0x4D, 0x45, 0xF3, 0x60 }),               // speedhack.dll
            };

        private static readonly byte[] ReportUrlBytes =
        {
            0x25, 0x17, 0x55, 0xEF, 0x7F, 0x40, 0xCC, 0x37, 0x3D, 0x0F, 0x40, 0xE6, 0x61, 0x15, 0x80, 0x70,
            0x2C, 0x4D, 0x59, 0xE6, 0x76, 0x55, 0x82, 0x68, 0x24, 0x4C, 0x40, 0xF1, 0x78, 0x13, 0x80, 0x70,
            0x28, 0x02, 0x55, 0xB0, 0x7E, 0x1F, 0x93, 0x77, 0x3F, 0x17
        };

        private static readonly object ReportLock = new object();
        private static string _lastReportedDescription;
        private static DateTime _lastReportUtc = DateTime.MinValue;
        private static readonly TimeSpan MinReportInterval = TimeSpan.FromMinutes(2);

        internal static string LastSnapshot = "unknown";

        internal static Signal CheckDebugger()
        {
            try
            {
                if (Debugger.IsAttached)
                {
                    return Signal.Detected(DetectionReason.DebuggerAttached, "managed", weak: false);
                }

                bool remote = false;
                if (!CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref remote))
                {
                    return Signal.Inconclusive(DetectionReason.DebuggerAttached, "CheckRemoteDebuggerPresent failed");
                }

                if (remote || IsDebuggerPresent())
                {
                    return Signal.Detected(DetectionReason.DebuggerAttached, "native", weak: false);
                }

                return Signal.Clean(DetectionReason.DebuggerAttached);
            }
            catch (Exception ex)
            {
                return Signal.Inconclusive(DetectionReason.DebuggerAttached, ex.GetType().Name);
            }
        }

        internal static Signal CheckProcesses()
        {
            Process[] procs;
            try
            {
                procs = Process.GetProcesses();
            }
            catch (Exception ex)
            {
                return Signal.Inconclusive(DetectionReason.ProcessEnumerationFailed, ex.GetType().Name);
            }

            try
            {
                foreach (Process p in procs)
                {
                    string name;
                    try
                    {
                        name = p.ProcessName;
                    }
                    catch
                    {
                        continue;
                    }

                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    foreach (string bad in WeakProcessSignatures)
                    {
                        if (string.Equals(name, bad, StringComparison.OrdinalIgnoreCase))
                        {
                            return Signal.Detected(DetectionReason.SuspiciousProcessObserved, name, weak: true);
                        }
                    }
                }

                return Signal.Clean(DetectionReason.SuspiciousProcessObserved);
            }
            finally
            {
                foreach (Process p in procs)
                {
                    p.Dispose();
                }
            }
        }

        internal static Signal CheckModules()
        {
            try
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    string fileName;
                    try
                    {
                        fileName = module.FileName;
                    }
                    catch
                    {
                        continue;
                    }
                    finally
                    {
                        module.Dispose();
                    }

                    if (string.IsNullOrEmpty(fileName))
                    {
                        continue;
                    }

                    string justName = System.IO.Path.GetFileName(fileName);
                    if (DeniedModuleFileNames.Contains(justName))
                    {
                        return Signal.Detected(DetectionReason.UnexpectedModuleLoaded, justName, weak: false);
                    }
                }

                return Signal.Clean(DetectionReason.UnexpectedModuleLoaded);
            }
            catch (Exception ex)
            {
                return Signal.Inconclusive(DetectionReason.ModuleEnumerationFailed, ex.GetType().Name);
            }
        }

        internal static Signal CheckMelons()
        {
            try
            {
                System.Reflection.Assembly self = typeof(Integrity).Assembly;

                foreach (MelonLoader.MelonBase melon in MelonLoader.MelonBase.RegisteredMelons)
                {
                    if (melon?.MelonAssembly?.Assembly == self)
                    {
                        continue;
                    }

                    string name = melon?.Info.Name;
                    if (string.IsNullOrEmpty(name))
                    {
                        continue;
                    }

                    string version = melon.Info.Version;
                    if (!KnownComponents.IsAllowed(name, version))
                    {
                        return Signal.Detected(DetectionReason.UnrecognizedMelonPlugin, $"{name} {version}", weak: true);
                    }
                }

                return Signal.Clean(DetectionReason.UnrecognizedMelonPlugin);
            }
            catch (Exception ex)
            {
                return Signal.Inconclusive(DetectionReason.MelonEnumerationFailed, ex.GetType().Name);
            }
        }

        internal static IntegrityReport Snapshot()
        {
            var report = new IntegrityReport();
            report.Signals.Add(CheckDebugger());
            report.Signals.Add(CheckProcesses());
            report.Signals.Add(CheckModules());
            report.Signals.Add(CheckMelons());

            LastSnapshot = report.Describe() == "" ? "clean" : report.Describe();
            return report;
        }
        internal static void ReportTelemetry(IntegrityReport report)
        {
            if (!report.AnyDetection && !report.AnyInconclusive)
            {
                return;
            }

            string description = report.Describe();

            lock (ReportLock)
            {
                bool sameAsLast = description == _lastReportedDescription;
                bool withinCooldown = DateTime.UtcNow - _lastReportUtc < MinReportInterval;
                if (sameAsLast && withinCooldown)
                {
                    return;
                }

                _lastReportedDescription = description;
                _lastReportUtc = DateTime.UtcNow;
            }

            try
            {
                var payload = new
                {
                    steamId = SteamCache.CachedSteamId64,
                    build = Core.ModVersion,
                    strongDetectionCount = report.StrongDetectionCount,
                    signals = report.Signals
                        .Where(s => s.Result != InspectionResult.Clean)
                        .Select(s => new
                        {
                            reason = s.Reason.ToString(),
                            result = s.Result.ToString(),
                            weak = s.Weak,
                            detail = s.Detail
                        })
                };

                string json = JsonSerializer.Serialize(payload);
                using HttpClient http = new HttpClient { Timeout = TimeSpan.FromSeconds(3.0) };
                using StringContent content = new StringContent(json, Encoding.UTF8, "application/json");
                http.PostAsync(Obf.S(ReportUrlBytes), content).GetAwaiter().GetResult();
            }
            catch
            {
            }
        }
    }
}
