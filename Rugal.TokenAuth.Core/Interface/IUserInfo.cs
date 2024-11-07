using Rugal.TokenAuth.Core.Model;
using System.Security.Claims;

namespace Rugal.TokenAuth.Core.Interface;

public interface IUserInfo
{
    public Guid UserId { get; }
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public DateTime TokenExpiredDatetime { get; }
    public IUserInfo SetClaims(IEnumerable<Claim> _Claims);
    public IUserInfo AddClaim(string Type, object Value, ClaimsValueType ValueType);
    public IUserInfo AddClaims(IEnumerable<Claim> Claims);
    public bool TryGetValue(string PropertyName, out string OutValue);
    public Dictionary<string, object> GetClaimsInfo();
}