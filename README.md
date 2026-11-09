# MochaPatcher2023

A MelonLoader mod that points the Rec Room client at [Mocha](https://playmocha.xyz),
a private-server reimplementation of the Rec Room backend, instead of the real one.

## Supported game version

**Only the `20230406` client build is supported.** The mod links directly against
`Il2Cpp*` interop assemblies generated from that exact build, so the types and
method signatures won't line up with any other version.

To target a different client version, dump that build with
[Il2CppDumper](https://github.com/Perfare/Il2CppDumper) (or run it through
[Il2CppInterop](https://github.com/BepInEx/Il2CppInterop)'s generator) to produce
fresh interop assemblies, point `MochaPatches.csproj`'s `GameDir` at a `gamedir/`
built from that dump, and rebuild. Some patches target method names Unity's
IL2CPP build renames per version, so expect to re-find those in a decompiler
against the new dump.

## Building

```
build.bat
```

or, for the obfuscated release build:

```
build.obfuscated.bat
```

Both expect `gamedir/gamedir/` next to the project (game install + MelonLoader +
that version's interop assemblies) — not checked into this repo.

## Obfuscation

The obfuscated build (`build.obfuscated.bat` -> Obfuscar, config in `Obfuscar.xml`)
is turned up as far as it goes without breaking the mod:

- **Everything renames.** `KeepPublicApi` is off, so types, namespaces and members all
  collapse to short garbage names (a/b/c). `UseUnicodeNames` is deliberately OFF — the
  Unicode variant produced an image MelonLoader rejects (see below). The mod still loads:
  MelonLoader finds it by the
  `[MelonInfo]` `typeof` token, not the type name, and Harmony finds its patches by
  attribute. The Harmony patch method names (`Prefix`, `Postfix`, `Transpiler`,
  `Finalizer`, `Prepare`, `TargetMethod`, `TargetMethods`) are the one thing kept, since
  Harmony resolves those by name.
- **Strings are XOR-hidden.** `HideStrings` encrypts every string literal in method
  bodies at build time and injects a decryptor, so URLs, header names, the blacklist
  words and the JSON keys are not readable in the DLL but are restored at runtime.
  Attribute strings (Harmony targets, `MelonInfo` text) stay in metadata and are left
  alone, which is why patching and discovery keep working.
- **Decoy namespace.** `ObfuscatedByTopLevelOpsecObf` (in `Decoy.cs`) is the one thing
  left in the clear — Obfuscar `SkipNamespace`s it. It's a red herring full of
  official-looking "guard / vault / entropy / kill switch" code that never runs and does
  nothing; `Core` pokes it once as a no-op so it isn't pruned.

`UseUnicodeNames` must stay `false`. With it on, MelonLoader's loader rejects the DLL
with `BadImageFormatException` under Proton/Wine (confirmed on a live 20230406 load);
names still garble to short ASCII with it off. `Obfuscar.xml`'s `AssemblySearchPath`s
point at the same `gamedir/` tree the csproj builds against, so no per-machine paths
need editing.

## Layout

- `Core.cs` — the mod's entry point
- `HarmonyPatches.cs` — the actual patches
- `PhotonConnection.cs` — fetches Mocha's live Photon connection details
- `SteamCache.cs` — reads the local Steam id, for tagging requests
- `Integrity.cs` — the mod's own tamper/debugger detection
- `MochaGuard/` — the MochaGuard anti-cheat watchdogs (see below)
- `Decoy.cs` — the `ObfuscatedByTopLevelOpsecObf` red-herring namespace (see Obfuscation)

## MochaGuard

As of **1.0.8** MochaGuard ships inside this mod instead of as its own MelonMod. An
assembly may only carry one `[MelonInfo]`, so MochaGuard's old mod class became
`MochaGuard.GuardRuntime`, a static runtime that `Core` starts and stops:
`OnInitializeMelon` calls `GuardRuntime.Start(this)` after the config fetch, the Steam
id load and the first integrity snapshot; `OnDeinitializeMelon` calls `Stop()`. The
eight watchdog threads, their start order and every interval are unchanged, and so is
`Punisher`'s kill path.

Two things keep the merged build from detecting itself:

- `GuardRuntime.Start` hands the host mod to `HarmonyPatchGuard.AllowHost`, which
  registers the Harmony instance id MelonLoader applies this mod's patches under.
  Without it every patch in `HarmonyPatches.cs` reads as a foreign patch and the first
  scan kills the game.
- `MochaPatches.dll` is a trusted module name in `Blacklist`, and `MochaGuard` is a
  known component in `Integrity`.

Do not ship the standalone `MochaGuard.dll` alongside this build — the guard would run
twice.

`Integrity.cs` and MochaGuard overlap in intent but not in mechanism, and both are
live: `Integrity` samples on the Unity thread and reports telemetry to the server,
MochaGuard runs its own threads and terminates the process locally.

### Enforcement posture

Detections split by confidence, so legitimate software on real players does not crash
the game (`Punisher.Report` logs a `DETECT` line; `Punisher.Kill` terminates):

- **Kill (high confidence):** a debugger attached; a process/window named like a known
  cheat tool (Cheat Engine, injectors, HTTP debuggers) via `ExternalGuard`; a module
  whose *name* matches a known cheat (`ModuleGuard` + `Blacklist.IsSuspiciousName`); a
  changed prologue on GameAssembly's own IL2CPP exports (`MemoryGuard`); a foreign
  Harmony patch on a *critical* method — process exit, the melon lifecycle,
  `Environment.*` (`HarmonyPatchGuard`).
- **Report only (false-positive-prone):** a changed prologue on a watched ntdll/kernel32
  API (`HookGuard`) — overlays and capture tools legitimately hook these; an
  unrecognized but un-named module (`ModuleGuard`) — overlays, capture, input software,
  AV; a foreign Harmony patch on an ordinary method (`HarmonyPatchGuard`) — another mod.

`Blacklist` trusts the game dir, all of Program Files, the Windows and Steam dirs, and
names the common legit injectors (Steam/Discord/GPU overlays, OBS `graphics-hook`,
RivaTuner `RTSSHooks`, ShadowPlay). A `mochaguard_off.txt` file next to `RecRoom.exe`
turns *every* kill into a log line — a testing/support escape hatch; do not ship it.

## Distribution

Build output (`bin/`, `obj/`, `dist/`) isn't committed. Publish the built DLL as a
release artifact instead.

## photon patching

in **20230406**, the normal client has Photon built directly into the game. to patch it, you have to dump the game and locate the obfuscated Unity/IL2CPP methods, such as `GBNKOFMAJPA`, then patch the relevant Photon connection code.

older versions work differently. instead of having the Photon connection logic handled entirely through those obfuscated client methods, they request the Photon connection information from the server through an endpoint like `/player/connection-info`.

so basically:

* **20230406** → Photon connection logic is handled in the client → requires dumping/locating the obfuscated methods to patch it.
* **newer versions** → Photon connection information is fetched from the server → doesn't require patching those client methods in the same way.
