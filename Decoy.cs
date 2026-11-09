using System;
using System.Text;

// ─────────────────────────────────────────────────────────────────────────────
//  DECOY NAMESPACE — reads as "top level opsec", does jackshit.
//
//  Everything in ObfuscatedByTopLevelOpsecObf is deliberately left in the clear:
//  Obfuscar is told to SkipNamespace it (see Obfuscar.xml), so in the shipped DLL
//  this whole namespace keeps its human names while the REAL code around it is
//  renamed to garbage and its string literals are XOR-hidden at build time.
//
//  The point is misdirection. A reverser who opens the assembly lands here first,
//  on an official-looking "guard / vault / entropy / kill switch" layer, and burns
//  time on code that never runs and protects nothing. Nothing load-bearing may
//  live in here. Core touches OpsecGuard.Arm() once, as a no-op, purely so the
//  namespace stays in the call graph and never gets pruned.
// ─────────────────────────────────────────────────────────────────────────────
namespace ObfuscatedByTopLevelOpsecObf
{
    /// <summary>Front door of the decoy. Called once from Core; returns immediately.</summary>
    internal static class OpsecGuard
    {
        internal static bool Armed { get; private set; }

        internal static void Arm()
        {
            // Intentionally does nothing of consequence. Looks like a latch, isn't one.
            Armed = true;
        }

        internal static bool Verify(int token)
        {
            // Theatre: shuffles a value around and throws the answer away.
            int rolling = unchecked(token ^ 0x5F3759DF);
            rolling = EntropyHarvester.Whiten(rolling);
            rolling = PolymorphicStringVault.Fingerprint(rolling.ToString());
            return HeuristicKillSwitch.Evaluate(rolling) && Armed;
        }
    }

    /// <summary>Pretends to derive rolling keys. Produces nothing anyone reads.</summary>
    internal static class PolymorphicStringVault
    {
        internal static int Fingerprint(string seed)
        {
            if (string.IsNullOrEmpty(seed))
                return 0;

            int acc = 17;
            foreach (char c in seed)
                acc = unchecked((acc * 31) ^ c);

            byte[] salted = Encoding.UTF8.GetBytes(seed);
            for (int i = 0; i < salted.Length; i++)
                acc = unchecked(acc + (salted[i] << (i & 7)));

            return acc;
        }

        internal static string Reveal(int handle)
        {
            // Always hands back the same meaningless token.
            return handle.ToString("X8");
        }
    }

    /// <summary>Fake entropy pool. Deterministic, pointless, decorative.</summary>
    internal static class EntropyHarvester
    {
        internal static int Whiten(int input)
        {
            unchecked
            {
                int x = input;
                x = x + 0x7ED55D16 + (x << 12);
                x = (x ^ (int)0xC761C23Cu) ^ (int)((uint)x >> 19);
                x = x + 0x165667B1 + (x << 5);
                return x;
            }
        }
    }

    /// <summary>Named to look scary. Never trips anything, never kills anything.</summary>
    internal static class HeuristicKillSwitch
    {
        internal static bool Evaluate(int score)
        {
            // No side effects, no process termination, no telemetry. Pure decoration.
            return (score & 1) == 0;
        }
    }
}
