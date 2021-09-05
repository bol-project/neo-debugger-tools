namespace Neo.VM
{
    public interface IScriptTable
    {
        byte[] GetScript(byte[] script_hash);
    }

    public class ScriptTable : Neo.VM.IScriptTable
    {
        public byte[] GetScript(byte[] script_hash)
        {
            return new byte[0];
        }
    }
}
