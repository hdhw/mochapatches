using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using MelonLoader;
using Microsoft.Win32;

namespace Mocha.Patch
{
    internal static class SteamCache
    {
        internal static string CachedSteamId64 = "0";

        internal static void Load()
        {
            foreach (string loginUsers in CandidatePaths())
            {
                try
                {
                    if (!File.Exists(loginUsers))
                    {
                        continue;
                    }

                    string id = ReadSteamId(File.ReadAllText(loginUsers));
                    if (id == null)
                    {
                        MelonLogger.Warning(
                            "SteamCache: no logged-in account in " + loginUsers);
                        continue;
                    }

                    CachedSteamId64 = id;
                    MelonLogger.Msg("SteamCache: steam id resolved from " + loginUsers);
                    return;
                }
                catch (Exception ex)
                {
                    MelonLogger.Warning(
                        "SteamCache: could not read " + loginUsers + " - " + ex.Message);
                }
            }

            // Left at "0", which the server reads as "no Steam id" and answers with the
            // outdated-patch error. Say so here, or the failure is invisible.
            MelonLogger.Error(
                "SteamCache: no loginusers.vdf found - X-Mocha-SteamId will be sent as 0 " +
                "and the server will reject the login.");
        }

        /// <summary>
        /// Where loginusers.vdf might be, most authoritative first.
        /// </summary>
        private static IEnumerable<string> CandidatePaths()
        {
            // Native Windows: the registry points at the Steam install.
            string steamPath = FindSteamPath();
            if (!string.IsNullOrEmpty(steamPath))
            {
                yield return Path.Combine(steamPath, "config", "loginusers.vdf");
            }

            // Proton/Wine: the prefix registry has no real Steam install to point at, so
            // the lookup above finds nothing. The Linux filesystem is mounted at Z:\, so
            // the real Steam config is reachable through it.
            foreach (string home in UnixHomes())
            {
                yield return Path.Combine(home, ".steam", "steam", "config", "loginusers.vdf");
                yield return Path.Combine(home, ".steam", "root", "config", "loginusers.vdf");
                yield return Path.Combine(home, ".local", "share", "Steam", "config", "loginusers.vdf");
                yield return Path.Combine(
                    home, ".var", "app", "com.valvesoftware.Steam",
                    ".local", "share", "Steam", "config", "loginusers.vdf");
            }
        }

        private static IEnumerable<string> UnixHomes()
        {
            foreach (string root in new[] { @"Z:\home", @"Z:\root" })
            {
                string[] homes;

                try
                {
                    homes = Directory.Exists(root)
                        ? Directory.GetDirectories(root)
                        : new string[0];
                }
                catch
                {
                    continue;
                }

                foreach (string home in homes)
                {
                    yield return home;
                }
            }
        }

        /// <summary>
        /// Pick the account from a loginusers.vdf. Steam names the account it launched the
        /// game for in SteamAppUser, so prefer that one; otherwise the MostRecent flag,
        /// otherwise the first entry.
        /// </summary>
        private static string ReadSteamId(string text)
        {
            string appUser = null;

            try
            {
                appUser = Environment.GetEnvironmentVariable("SteamAppUser");
            }
            catch
            {
            }

            string first = null;
            string mostRecent = null;

            foreach (Match block in Regex.Matches(text, "\"(7656\\d{13})\"\\s*\\{([^{}]*)\\}"))
            {
                string id = block.Groups[1].Value;
                string body = block.Groups[2].Value;

                if (first == null)
                {
                    first = id;
                }

                if (!string.IsNullOrEmpty(appUser))
                {
                    Match name = Regex.Match(body, "\"AccountName\"\\s*\"([^\"]*)\"");
                    if (name.Success &&
                        string.Equals(name.Groups[1].Value, appUser, StringComparison.OrdinalIgnoreCase))
                    {
                        return id;
                    }
                }

                if (mostRecent == null &&
                    Regex.IsMatch(body, "\"MostRecent\"\\s*\"1\""))
                {
                    mostRecent = id;
                }
            }

            return mostRecent ?? first;
        }

        private static string FindSteamPath()
        {
            try
            {
                using RegistryKey hkcu = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
                object p = hkcu?.GetValue("SteamPath");
                if (p is string s1 && Directory.Exists(s1))
                {
                    return s1;
                }
            }
            catch
            {
            }

            try
            {
                using RegistryKey hklm = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam");
                object p = hklm?.GetValue("InstallPath");
                if (p is string s2 && Directory.Exists(s2))
                {
                    return s2;
                }
            }
            catch
            {
            }

            return null;
        }
    }
}
