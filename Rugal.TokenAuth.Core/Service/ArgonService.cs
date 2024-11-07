using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;
using Rugal.TokenAuth.Core.Model;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace Rugal.TokenAuth.Core.Service;

public class ArgonService
{
    private readonly ArgonSetting Setting;
    public ArgonService(IOptions<ArgonSetting> Setting)
    {
        this.Setting = Setting?.Value ?? new ArgonSetting();
    }
    public GenerateHashResult GenerateHash(char[] SecureArray)
    {
        var Salt = new byte[Setting.SaltLength ?? 16];
        using var Rnd = RandomNumberGenerator.Create();
        Rnd.GetBytes(Salt);
        var Hash = BaseHash(SecureArray, Salt);
        Array.Clear(SecureArray, 0, SecureArray.Length);
        return new GenerateHashResult(Salt, Hash);
    }
    public bool VerifyHash(char[] SecureArray, byte[] Hash, byte[] Salt)
    {
        var GetHash = BaseHash(SecureArray, Salt);
        var IsVerify = StructuralComparisons.StructuralEqualityComparer.Equals(GetHash, Hash);
        return IsVerify;
    }
    private byte[] BaseHash(char[] SecureArray, byte[] Salt)
    {
        using var Hasher = new Argon2id(Encoding.UTF8.GetBytes(SecureArray));
        Hasher.Salt = Salt;
        Hasher.DegreeOfParallelism = Setting.DegreeOfParallelism ?? 8;
        Hasher.MemorySize = Setting.MemorySize ?? 65536;
        Hasher.Iterations = Setting.Iterations ?? 4;
        var Result = Hasher.GetBytes(Setting.HashLength ?? 32);
        return Result;
    }
}
