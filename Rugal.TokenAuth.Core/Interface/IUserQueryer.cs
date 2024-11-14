using Rugal.TokenAuth.Core.Model;

namespace Rugal.TokenAuth.Core.Interface;

public interface IUserQueryer
{
    public bool QueryUserClaims(Guid UserId, out Dictionary<string, object> Claims, out string Message);
}
