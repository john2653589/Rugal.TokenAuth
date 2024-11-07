namespace Rugal.TokenAuth.Core.Model;
public class ArgonSetting
{
    public int? DegreeOfParallelism { get; set; } = 8;
    public int? MemorySize { get; set; } = 65536;
    public int? Iterations { get; set; } = 4;
    public int? SaltLength { get; set; } = 16;
    public int? HashLength { get; set; } = 32;
}

public class GenerateHashResult
{
    public byte[] Salt { get; set; }
    public byte[] Hash { get; set; }
    public GenerateHashResult(byte[] Salt, byte[] Hash)
    {
        this.Salt = Salt;
        this.Hash = Hash;
    }
}