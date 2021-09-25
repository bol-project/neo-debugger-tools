using Neo.VM;
using Neo.Emulation.Utils;
using System;
using System.Diagnostics;
using System.Text;
using Neo.Lux.Cryptography;
using System.Collections;
using System.Collections.Concurrent;

namespace Neo.Emulation.API
{
    public static class Runtime
    {
        public static KeyPair invokerKeys;

        public static ConcurrentDictionary<Emulator,Action<string>> OnLogMessage = new ConcurrentDictionary<Emulator, Action<string>>();

        [Syscall("Neo.Runtime.GetTrigger")]
        public static bool GetTrigger(ExecutionEngine engine)
        {
            var emulator = engine.GetEmulator();
            TriggerType result = emulator.currentTrigger;

            engine.EvaluationStack.Push((int)result);
            return true;
        }

        [Syscall("Neo.Runtime.GetTime")]
        public static bool GetTime(ExecutionEngine engine)
        {
            var emulator = engine.GetEmulator();
            uint result = emulator.timestamp;

            engine.EvaluationStack.Push(result);
            return true;
        }

        [Syscall("Neo.Runtime.CheckWitness", 0.2)]
        public static bool CheckWitness(ExecutionEngine engine)
        {
            byte[] hashOrPubkey = engine.EvaluationStack.Pop().GetByteArray();

            bool result;

            string matchType;

            var emulator = engine.GetEmulator();

            if (hashOrPubkey.Length == 20) // script hash
            {
                matchType = "Script Hash";

                if (invokerKeys != null)
                {
                    result = invokerKeys.signatureHash.ToArray().ByteMatch(hashOrPubkey);
                }
                else
                {
                    result = false;
                }
            }
            else if (hashOrPubkey.Length == 33) // public key
            {
                matchType = "Public Key";

                if (invokerKeys != null)
                {
                    result = invokerKeys.CompressedPublicKey.ByteMatch(hashOrPubkey);
                }
                else
                {
                    result = false;
                }
            }
            else
            {
                matchType = "Unknown";
                result = false;
            }

            if (emulator.checkWitnessMode != CheckWitnessMode.Default)
            {
                if (emulator.checkWitnessMode == CheckWitnessMode.AlwaysFalse)
                {
                    result = false;
                }
                else
                if (emulator.checkWitnessMode == CheckWitnessMode.AlwaysTrue)
                {
                    result = true;
                }

                matchType += " / Forced";
            }

            DoLog($"Checking Witness [{matchType}]: {FormattingUtils.OutputData(hashOrPubkey, false)} => {result}", engine.GetEmulator());

            engine.EvaluationStack.Push(new VM.Types.Boolean(result));
            return true;
        }

        [Syscall("Neo.Runtime.Notify")]
        public static bool Notify(ExecutionEngine engine)
        {
            var something = engine.EvaluationStack.Pop();
            var result = FormattingUtils.StackItemAsString(something, true);
            DoLog(result, engine.GetEmulator());
            return true;
        }

        [Syscall("Neo.Runtime.Log")]
        public static bool Log(ExecutionEngine engine)
        {
            var msg = engine.EvaluationStack.Pop();
            DoLog(FormattingUtils.StackItemAsString(msg), engine.GetEmulator());
            return true;
        }

        private static void DoLog(string msg, Emulator emulator)
        {
            Debug.WriteLine(msg);

            if (OnLogMessage.TryGetValue(emulator, out var action))
                action(msg);            
        }
    }
}
