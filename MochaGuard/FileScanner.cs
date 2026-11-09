using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace MochaGuard
{
    internal static class FileScanner
    {
        private static string _gameDir;
        private static readonly HashSet<string> _scanned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public static void Init(string gameDir)
        {
            _gameDir = gameDir;
        }

        public static void Scan()
        {
            try
            {
                var drives = new StringBuilder(512);
                uint len = Native.GetLogicalDriveStringsW((uint)drives.Capacity, drives);
                if (len > 0)
                {
                    string all = drives.ToString(0, (int)len);
                    string[] parts = all.Split('\0');
                    foreach (var d in parts)
                    {
                        if (string.IsNullOrEmpty(d))
                            continue;
                        try
                        {
                            uint type = Native.GetDriveTypeW(d);
                            if (type != 2 && type != 3 && type != 4 && type != 6)
                                continue;

                            ScanDir(d, 0);
                        }
                        catch { }
                    }
                }

                if (!string.IsNullOrEmpty(_gameDir))
                    ScanDir(_gameDir, 0);
            }
            catch (Exception ex) { Punisher.LogWarn("FileScanner.Scan ex: " + ex.Message); }
        }

        private static void ScanDir(string dir, int depth)
        {
            if (depth > 3)
                return;

            try
            {
                var findData = new Native.WIN32_FIND_DATA();
                string pattern = Path.Combine(dir, "*");
                IntPtr hFind = Native.FindFirstFileW(pattern, out findData);
                if (hFind == (IntPtr)(-1) || hFind == IntPtr.Zero)
                    return;

                try
                {
                    do
                    {
                        string name = findData.cFileName;
                        if (name == "." || name == "..")
                            continue;

                        string fullPath = Path.Combine(dir, name);

                        if ((findData.dwFileAttributes & 0x10) != 0)
                        {
                            try { ScanDir(fullPath, depth + 1); } catch { }
                        }
                        else
                        {
                            string lower = name.ToLowerInvariant();

                            foreach (var sus in Blacklist.SuspiciousFileNames)
                            {
                                if (lower.Contains(sus))
                                {
                                    foreach (var ext in Blacklist.SuspiciousFileExtensions)
                                    {
                                        if (lower.EndsWith(ext))
                                        {
                                            string key = fullPath.ToLowerInvariant();
                                            lock (_scanned)
                                            {
                                                if (_scanned.Contains(key))
                                                    return;
                                                _scanned.Add(key);
                                            }

                                            Punisher.LogWarn($"Suspicious file: {fullPath}");
                                            Punisher.Kill($"file:{name}");
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    } while (Native.FindNextFileW(hFind, out findData));
                }
                finally
                {
                    Native.FindClose(hFind);
                }
            }
            catch { }
        }
    }
}
