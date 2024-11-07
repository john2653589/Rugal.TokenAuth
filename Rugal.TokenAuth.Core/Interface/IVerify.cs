using System.Security.Claims;

namespace Rugal.TokenAuth.Core.Interface;

public interface IBlackTokenVerfiy
{
    public bool VerifyBlackToken(string Token, IEnumerable<Claim> Claims);
}
public interface IAuthVerfiy
{
    public bool VerifyAuth(string Token, IEnumerable<Claim> Claims);
}
