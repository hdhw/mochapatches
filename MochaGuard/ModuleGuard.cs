using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace MochaGuard
{
    internal static class ModuleGuard
    {
        private static readonly HashSet<string> _seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly object _lock = new object();

        public static void Start()
        {
            try
            {
                var proc = Process.GetCurrentProcess();
                foreach (ProcessModule m in proc.Modules)
                {
                    string name = Path.GetFileName(m.FileName) ?? "";
                    if (!string.IsNullOrEmpty(name))
                    {
                        lock (_lock)
                            _seen.Add(name.ToLowerInvariant());
                        Punisher.Log($"Initial module: {name} @ {m.FileName}");
                    }
                }
            }
            catch (Exception ex) { Punisher.LogWarn("ModuleGuard.Start ex: " + ex.Message); }
        }

        public static void Scan()
        {
            try
            {
                var proc = Process.GetCurrentProcess();
                foreach (ProcessModule m in proc.Modules)
                {
                    string file = m.FileName ?? "";
                    string name = Path.GetFileName(file) ?? "";
                    if (string.IsNullOrEmpty(name))
                        continue;

                    string lower = name.ToLowerInvariant();

                    lock (_lock)
                    {
                        if (_seen.Contains(lower))
                            continue;
                        _seen.Add(lower);
                    }

                    Punisher.Log($"New module: {name} @ {file}");

                    if (Blacklist.IsTrustedModuleName(name))
                        continue;

                    if (Blacklist.IsTrustedPath(file))
                        continue;

                    // A module whose NAME matches a known cheat/injector is high
                    // confidence: kill.
                    if (Blacklist.IsSuspiciousName(name))
                    {
                        Punisher.Kill($"mod:{name}");
                        return;
                    }

                    // An unrecognized-but-unnamed module is NOT high confidence: on real
                    // players this is overlays, capture tools, input software, AV, etc.
                    // Report it, do not kill, and keep scanning (no early return, so one
                    // odd module doesn't blind the scanner to a later named cheat).
                    Punisher.Report($"inj:{name}@{file}");
                    continue;
                }
            }
            catch (Exception ex) { Punisher.LogWarn("ModuleGuard.Scan ex: " + ex.Message); }
        }
    }
}
