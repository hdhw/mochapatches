using System;
using System.Net.Http;
using System.Text.Json;
using MelonLoader;

namespace Mocha.Patch
{
    internal static class PhotonConnection
    {
        private const string ConfigUrl = "https://playmocha.xyz/api/photon/config";
        internal static string RealtimeAppId = "94e5bc5c-d19b-4651-b3c0-e0f7758c17e1";
        internal static string VoiceAppId = "bfa91264-1580-4e63-b355-77404b95e33e";
        internal static string AppVersion = "20230406_prod";
        internal static string Region = "us";
        internal static void FetchNow()
        {
            try
            {
                using HttpClient http = new HttpClient { Timeout = TimeSpan.FromSeconds(5.0) };
                string json = http.GetStringAsync(ConfigUrl).GetAwaiter().GetResult();
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement root = doc.RootElement;
                if (root.TryGetProperty("RealtimeAppId", out JsonElement r) && r.ValueKind == JsonValueKind.String)
                {
                    RealtimeAppId = r.GetString();
                }
                if (root.TryGetProperty("VoiceAppId", out JsonElement v) && v.ValueKind == JsonValueKind.String)
                {
                    VoiceAppId = v.GetString();
                }
                if (root.TryGetProperty("AppVersion", out JsonElement av) && av.ValueKind == JsonValueKind.String)
                {
                    AppVersion = av.GetString();
                }
                if (root.TryGetProperty("Region", out JsonElement rg) && rg.ValueKind == JsonValueKind.String)
                {
                    Region = rg.GetString();
                }
            }
            catch (Exception ex)
            {
                MelonLogger.Warning("PhotonConnection: /api/photon/config fetch failed (" + ex.Message + "); using built-in app ids.");
            }
        }
    }
}
