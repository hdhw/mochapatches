using System;
using System.Collections.Generic;
using System.IO;

namespace MochaGuard
{
    internal static class Blacklist
    {
        private static string _gameDir;
        private static readonly HashSet<string> _trustedModuleNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "mocha.dll",
            "mochaguard.dll",
            "mochapatches.dll",
            "gameassembly.dll",
            "unityplayer.dll",
            "recroom.exe",
            "easyanticheat.dll",
            "easyanticheat_x64.so",
            "melonloader.dll",
            "0harmony.dll",
            "il2cppinterop.runtime.dll",
            "il2cppinterop.common.dll",
            // Steam client + overlay. These load into every Steam game from Steam's
            // own directory; without them the module scanner kills the game the moment
            // Steam injects its client DLL. Confirmed KILL on a live 20230406 launch.
            "steamclient64.dll",
            "steamclient.dll",
            "steamoverlayvulkanlayer64.dll",
            "steamoverlayvulkanlayer.dll",
            "gameoverlayrenderer64.dll",
            "gameoverlayrenderer.dll",
            // Common legitimate software that injects/hooks into games. Without these,
            // the guard would flag (now report, not kill) huge numbers of honest players.
            "discordhook64.dll",
            "discordhook.dll",
            "graphics-hook64.dll",           // OBS / game capture
            "graphics-hook32.dll",
            "rtsshooks64.dll",               // RivaTuner Statistics Server / MSI Afterburner
            "rtsshooks.dll",
            "nvspcap64.dll",                 // NVIDIA ShadowPlay / GeForce Experience
            "nvspcap.dll",
            "nvinject.dll",
            "amdxc64.dll",                   // AMD overlay
            "openvr_api.dll",                // SteamVR
        };

        private static readonly string[] _suspiciousNameParts = new string[]
        {
            "cheatengine", "cheat engine",
            "xenos", "extremeinjector", "ghinjector", "scylla",
            "unityexplorer", "cinematicunityexplorer", "universelib",
            "reclass", "artmoney", "cosmos", "cozmoo",
            "minhook", "detour",
            "frida", "gadget",
            "dnspy", "ilspy", "dotpeek", "de4dot",
            "megaseconds",
        };

        private static readonly string[] _suspiciousProcessNames = new string[]
        {
            "cheatengine", "cheat engine", "x64dbg", "x32dbg", "ollydbg", "windbg", "immunity",
            "dnspy", "ilspy", "dotpeek", "justdecompile", "de4dot",
            "hxd", "hexedit", "hexeditor",
            "httpdebugger", "httpdebuggerui", "fiddler", "charles", "burpsuite", "wireshark", "mitmproxy",
            "processhacker", "systeminformer",
            "extremeinjector", "xenos", "ghinjector", "scylla",
            "unityexplorer", "cinematicunityexplorer", "universelib",
            "artmoney", "reclass", "cosmos", "cozmoo", "megaseconds",
            "apimonitor", "regmon", "filemon", "tcpview", "autoruns",
            "ida", "ida64", "idaq", "ghidra",
            "frida", "frida-server", "frida-trace",
            "processhacker2",
        };

        private static readonly string[] _suspiciousWindowKeywords = new string[]
        {
            "cheat engine", "x64dbg", "x32dbg", "ollydbg",
            "dnspy", "ilspy", "hxd",
            "http debugger", "http debug", "fiddler",
            "process hacker", "system informer",
            "unity explorer", "cinematic unity explorer",
            "extreme injector", "xenos injector", "gh injector",
            "reclass", "artmoney", "cosmos",
            "ida -", "ghidra",
            "first scan", "next scan", "memory view",
            "find what writes", "find what accesses",
            "hex dump", "disassembly",
        };

        private static readonly string[] _suspiciousFileVersionKeywords = new string[]
        {
            "cheat engine", "x64dbg", "dnspy", "ilspy", "hxd",
            "http debugger", "fiddler", "process hacker",
            "extreme injector", "xenos injector", "gh injector",
            "unity explorer", "cinematic unity explorer",
        };

        private static readonly string[] _cheatEngineWindowKeywords = new string[]
        {
            "first scan", "next scan", "new scan", "memory view",
            "find what writes", "find what accesses", "find out what",
            "hex dump", "disassembly",
            "cheat engine",
        };

        private static readonly string[] _httpDebuggerKeywords = new string[]
        {
            "http debugger", "httpdebugger",
        };

        private static readonly string[] _httpDebuggerProcessNames = new string[]
        {
            "httpdebugger", "httpdebuggerui", "httpdebuggersvc",
        };

        private static readonly string[] _httpDebuggerDriverNames = new string[]
        {
            "httpdebugger",
        };

        private static readonly string[] _suspiciousFileNames = new string[]
        {
            "cheatengine", "xenos", "extremeinjector", "ghinjector",
            "unityexplorer", "reclass", "artmoney",
            "frida", "gadget",
            "dnspy", "ilspy",
        };

        private static readonly string[] _suspiciousFileExtensions = new string[]
        {
            ".exe", ".dll", ".sys",
        };

        public static void SetGameDir(string dir)
        {
            _gameDir = dir;
            if (!_gameDir.EndsWith("\\") && !_gameDir.EndsWith("/"))
                _gameDir += "\\";
        }

        public static string GameDir => _gameDir;

        public static bool IsTrustedModuleName(string name)
        {
            if (string.IsNullOrEmpty(name))
                return false;
            return _trustedModuleNames.Contains(name);
        }

        public static bool IsSuspiciousName(string name)
        {
            if (string.IsNullOrEmpty(name))
                return false;
            string lower = name.ToLowerInvariant();
            foreach (var part in _suspiciousNameParts)
            {
                if (lower.Contains(part))
                    return true;
            }
            return false;
        }

        public static bool IsTrustedPath(string path)
        {
            if (string.IsNullOrEmpty(path))
                return false;

            try
            {
                string lower = path.ToLowerInvariant();

                if (!string.IsNullOrEmpty(_gameDir) && lower.StartsWith(_gameDir.ToLowerInvariant()))
                    return true;

                string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
                if (lower.StartsWith(winDir))
                    return true;

                string pf = (Environment.GetEnvironmentVariable("ProgramFiles") ?? "C:\\Program Files").ToLowerInvariant();
                string pf86 = (Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? "C:\\Program Files (x86)").ToLowerInvariant();

                // Trust everything under Program Files. Installed software (Steam,
                // Discord, OBS, Afterburner, GPU drivers, antivirus) lives here and
                // legitimately loads into games; cheats overwhelmingly run from Downloads,
                // Temp, Desktop or AppData instead. This is the single biggest reducer of
                // false positives on real players.
                if (lower.StartsWith(pf + "\\") || lower.StartsWith(pf86 + "\\"))
                    return true;

                if (lower.StartsWith(pf + "\\dotnet"))
                    return true;
                if (lower.StartsWith(pf86 + "\\dotnet"))
                    return true;
                if (lower.StartsWith(pf + "\\microsoft"))
                    return true;
                if (lower.StartsWith(pf86 + "\\microsoft"))
                    return true;
                if (lower.StartsWith(winDir + "\\microsoft.net"))
                    return true;

                if (lower.Contains("\\melonloader\\"))
                    return true;
                if (lower.Contains("\\userlibs\\"))
                    return true;
                if (lower.Contains("\\recroom_data\\"))
                    return true;
                if (lower.Contains("\\plugins\\"))
                    return true;

                if (lower.Contains("\\dotnet\\"))
                    return true;
                if (lower.Contains("\\microsoft.net\\"))
                    return true;
                if (lower.Contains("\\windows\\system32\\"))
                    return true;
                if (lower.Contains("\\windows\\syswow64\\"))
                    return true;

                if (lower.Contains("\\steam\\steamapps\\"))
                    return true;
                if (lower.Contains("\\common\\recroom\\"))
                    return true;
                // Steam's own install dir (steamclient64.dll, the overlay, etc.). A
                // real injector does not live inside the Steam client directory, and
                // trusting it stops the scanner from killing the game over Steam's own
                // modules. Covers "…\Program Files (x86)\Steam\…" and library folders.
                if (lower.Contains("\\steam\\"))
                    return true;
            }
            catch { }

            return false;
        }

        public static string[] SuspiciousProcessNames => _suspiciousProcessNames;
        public static string[] SuspiciousWindowKeywords => _suspiciousWindowKeywords;
        public static string[] SuspiciousFileVersionKeywords => _suspiciousFileVersionKeywords;
        public static string[] CheatEngineWindowKeywords => _cheatEngineWindowKeywords;
        public static string[] HttpDebuggerKeywords => _httpDebuggerKeywords;
        public static string[] HttpDebuggerProcessNames => _httpDebuggerProcessNames;
        public static string[] HttpDebuggerDriverNames => _httpDebuggerDriverNames;
        public static string[] SuspiciousFileNames => _suspiciousFileNames;
        public static string[] SuspiciousFileExtensions => _suspiciousFileExtensions;
    }
}
