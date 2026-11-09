using System;
using HarmonyLib;
using Il2Cpp;
using Il2CppBestHTTP;
using Il2CppOrg.BouncyCastle.Crypto.Tls;
using Il2CppPhoton.Realtime;
using Il2CppRecRoom.AntiCheat;
using MelonLoader;
using Mocha.Patch;
using Uri = Il2CppSystem.Uri;

namespace MochaPatches
{
    public class HarmonyPatches
    {
        [HarmonyPatch(typeof(HTTPManager), "SendRequest", new Type[]
        {
            typeof(HTTPRequest)
        })]
        internal class NSPatch
        {
            private static void Prefix(ref HTTPRequest request)
            {
                bool flag = request.Uri.ToString().Contains("githubusercontent");
                if (flag)
                {
                    request.Uri = new Uri("https://playmocha.xyz/nameserver");
                }
                Uri uri = request.Uri;
                MelonLogger.Msg("Caught request: " + ((uri != null) ? uri.ToString() : null));

                request.SetHeader("X-Mocha-SteamId", SteamCache.CachedSteamId64);
                request.SetHeader("X-Mocha-Build", Core.ModVersion);
                request.SetHeader("X-Mocha-Sig", Integrity.LastSnapshot);
            }
        }

        [HarmonyPatch(typeof(PUNNetworkManager), "OIMACPCFIKN")]
        internal class PhotonPatch
        {
            private static void Postfix(string ALENEHILMJK, ref AppSettings __result)
            {
                __result = new AppSettings
                {
                    AppIdRealtime = PhotonConnection.RealtimeAppId,
                    AppIdVoice = PhotonConnection.VoiceAppId,
                    AppVersion = PhotonConnection.AppVersion,
                    FixedRegion = PhotonConnection.Region
                };
            }
        }

        [HarmonyPatch(typeof(HDEJKABEHLO), "GBNKOFMAJPA")]
        internal class PhotonPatch2
        {
            private static void Postfix(ref AppSettings __result)
            {
                __result = new AppSettings
                {
                    AppIdRealtime = PhotonConnection.RealtimeAppId,
                    AppIdVoice = PhotonConnection.VoiceAppId,
                    AppVersion = PhotonConnection.AppVersion,
                    FixedRegion = PhotonConnection.Region
                };
            }
        }

        [HarmonyPatch(typeof(LEALBOODIEE), "GBNKOFMAJPA")]
        internal class PhotonPatch3
        {
            private static void Postfix(ref AppSettings __result)
            {
                __result = new AppSettings
                {
                    AppIdRealtime = PhotonConnection.RealtimeAppId,
                    AppIdVoice = PhotonConnection.VoiceAppId,
                    AppVersion = PhotonConnection.AppVersion,
                    FixedRegion = PhotonConnection.Region
                };
            }
        }

        [HarmonyPatch(typeof(LegacyTlsAuthentication), "NotifyServerCertificate")]
        internal class AlwaysVerifyTLSPatch
        {
            private static bool Prefix()
            {
                return false;
            }
        }

        [HarmonyPatch(typeof(EACManager), "GenerateChallengeResponse")]
        internal class EACPatch
        {
            private static bool Prefix(ref string __result)
            {
                __result = "\"AQAAAGd9O3h2ynQW6Y/1MhdZC8VoHygxyTzmiRvAfpiRtJEBQ+NVaXMStRTsYQk42H1hbB7NGKhIpgfShk+ADtRW9EU/YF5320eGmINJZAqkm3pyX9QF/w1QT4IB2EQfOqTfpryQ3QFchXYqDgg/SbX+/X9mgzssbflIw3OAK+c=\"";
                return false;
            }
        }
    }
}
