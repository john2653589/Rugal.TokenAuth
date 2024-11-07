using Rugal.TokenAuth.Core.Model;

namespace Rugal.TokenAuth.Core.Interface;

public interface IUserQueryer
{
    public Dictionary<string, object> QueryUserClaims(Guid UserId);
}
