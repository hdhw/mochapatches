using System;
using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Il2Cpp;
using Il2CppRecRoom.AntiCheat;
using Il2CppSystem.Reflection;
using MelonLoader;
using UnityEngine;

[assembly: MelonInfo(typeof(Mocha.Patch.Core), "some shitty patch lmao", "1.0.8", "Mocha")]
[assembly: MelonColor(255, 120, 200, 255)]

namespace Mocha.Patch
{
    public class Core : MelonMod
    {
        public const string ModVersion = "1.0.8";

        private static readonly HttpClient _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10.0)
        };

        private const string ConfigUrl = "https://playmocha.xyz/api/config/v2";

        private const float CheckIntervalSeconds = 1f;
        private const float UpdateCheckIntervalSeconds = 300f;
        private const float IntegrityCheckIntervalSeconds = 20f;

        private float _pollTimer;
        private float _updateTimer = 300f;
        private bool _updateChecking;
        private float _injectionCheckTimer;
        private float _antiTamperTimer;
        private bool _fetching;
        private volatile int _polledMinutes = int.MinValue;
        private int _lastConfigMinutes = int.MinValue;
        private DateTime _deadlineUtc;
        private bool _active;
        private int _lastShownMilestone = -1;
        private string _updateVersion;
        private bool _updateRequired;

        public override void OnInitializeMelon()
        {
            // No-op: keeps the ObfuscatedByTopLevelOpsecObf decoy in the call graph so it
            // survives to the shipped DLL as a red herring. Arms nothing, does nothing.
            ObfuscatedByTopLevelOpsecObf.OpsecGuard.Arm();

            LoggerInstance.Msg("mocha patch " + ModVersion + " loaded");
            PhotonConnection.FetchNow();
            SteamCache.Load();
            Integrity.Snapshot();

            // MochaGuard ships inside this assembly as of 1.0.8. It used to be its own
            // MelonMod; it is started last so the config fetch, Steam id and the first
            // integrity snapshot are already done before its watchdog threads spin up.
            MochaGuard.GuardRuntime.Start(this);
        }

        public override void OnDeinitializeMelon()
        {
            MochaGuard.GuardRuntime.Stop();
            base.OnDeinitializeMelon();
        }

        public override void OnUpdate()
        {
            _pollTimer += Time.deltaTime;
            if (_pollTimer >= CheckIntervalSeconds && !_fetching)
            {
                _pollTimer = 0f;
                _ = FetchAsync();
            }

            _injectionCheckTimer += Time.deltaTime;
            _antiTamperTimer += Time.deltaTime;
            if (_injectionCheckTimer >= IntegrityCheckIntervalSeconds)
            {
                _injectionCheckTimer = 0f;
                _antiTamperTimer = 0f;
                IntegrityReport report = Integrity.Snapshot();
                if (!report.AllClean)
                {
                    MelonLogger.Warning("integrity check: " + report.Describe());
                    Integrity.ReportTelemetry(report);
                }
            }

            if (_active)
            {
                int minutesRemaining = (int)Math.Ceiling((_deadlineUtc - DateTime.UtcNow).TotalMinutes);
                if (minutesRemaining <= 0)
                {
                    ApplyMaintenance(0, show: false);
                    _active = false;
                    _lastShownMilestone = -1;
                }
                else if (IsMilestone(minutesRemaining) && minutesRemaining != _lastShownMilestone)
                {
                    ApplyMaintenance(minutesRemaining, show: true);
                    _lastShownMilestone = minutesRemaining;
                }
            }
        }

        private static bool IsMilestone(int m)
        {
            return m == 60 || m == 30 || m == 15 || (m >= 0 && m <= 10);
        }

        [DebuggerStepThrough]
        private async Task FetchAsync()
        {
            if (_fetching)
            {
                return;
            }

            _fetching = true;
            try
            {
                using HttpResponseMessage response = await _http.GetAsync(ConfigUrl);
                response.EnsureSuccessStatusCode();

                string json = await response.Content.ReadAsStringAsync();
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement root = doc.RootElement;

                int minutes = root.TryGetProperty("ServerMaintenance", out JsonElement sm)
                    && sm.ValueKind == JsonValueKind.Object
                    && sm.TryGetProperty("StartsInMinutes", out JsonElement m)
                    && m.ValueKind == JsonValueKind.Number
                    ? m.GetInt32()
                    : int.MinValue;

                _polledMinutes = minutes;

                if (minutes != _lastConfigMinutes)
                {
                    _lastConfigMinutes = minutes;
                    if (minutes >= 0)
                    {
                        _deadlineUtc = DateTime.UtcNow.AddMinutes(minutes);
                        _active = true;
                        _lastShownMilestone = -1;
                    }
                    else
                    {
                        ApplyMaintenance(0, show: false);
                        _active = false;
                        _lastShownMilestone = -1;
                    }
                }
            }
            catch (Exception ex)
            {
                MelonLogger.Warning("FetchAsync failed: " + ex.Message);
            }
            finally
            {
                _fetching = false;
            }
        }

        private static bool ApplyMaintenance(int minutes, bool show)
        {
            bool result;
            try
            {
                Il2CppSystem.Type type = Il2CppSystem.Type.GetType("SessionManager");
                bool flag = type == null;
                if (flag)
                {
                    MelonLogger.Warning("SessionManager il2cpp type not found");
                    result = false;
                }
                else
                {
                    UnityEngine.Object @object = UnityEngine.Object.FindObjectOfType(type);
                    bool flag2 = @object == null;
                    if (flag2)
                    {
                        result = false;
                    }
                    else
                    {
                        BindingFlags bindingFlags = (BindingFlags)52;
                        FieldInfo field = type.GetField("serverMaintenanceMinuteVOs", bindingFlags);
                        bool flag3 = field == null;
                        if (flag3)
                        {
                            MelonLogger.Warning("serverMaintenanceMinuteVOs field not found");
                            result = false;
                        }
                        else
                        {
                            Il2CppSystem.Type elementType = field.FieldType.GetElementType();
                            int num = show ? 1 : 0;
                            Il2CppSystem.Array array = Il2CppSystem.Array.CreateInstance(elementType, num);
                            if (show)
                            {
                                Il2CppSystem.Object object2 = Il2CppSystem.Activator.CreateInstance(elementType);
                                FieldInfo field2 = elementType.GetField("StartsInMinutes", bindingFlags);
                                bool flag4 = field2 != null;
                                if (flag4)
                                {
                                    Il2CppSystem.Int32 @int = default(Il2CppSystem.Int32);
                                    @int.m_value = minutes;
                                    Il2CppSystem.Object object3 = @int.BoxIl2CppObject();
                                    field2.SetValue(object2, object3);
                                }
                                array.SetValue(object2, 0);
                            }
                            field.SetValue(@object, array);
                            result = true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MelonLogger.Warning("applymaintenance failed son im crine : " + ex.Message);
                result = false;
            }
            return result;
        }

        public override void OnSceneWasLoaded(int buildIndex, string sceneName)
        {
            base.OnSceneWasLoaded(buildIndex, sceneName);
            MelonLogger.Msg($"Scene Loaded: {sceneName} (BuildIndex: {buildIndex})");

            bool flag = sceneName != "TitleScreen" && sceneName != "empty";
            if (flag)
            {
                CheatManager cheatManager = UnityEngine.Object.FindObjectOfType<CheatManager>();
                UnityEngine.Object.Destroy((UnityEngine.Object)(((UnityEngine.Object)cheatManager != null) ? cheatManager.gameObject : null));

                EACManager eacmanager = UnityEngine.Object.FindObjectOfType<EACManager>();
                UnityEngine.Object.Destroy((UnityEngine.Object)(((UnityEngine.Object)eacmanager != null) ? eacmanager.gameObject : null));
            }
        }
    }
}
