using Microsoft.Extensions.Options;
using Rugal.TokenAuth.Core.Interface;
using System.Security.Claims;

namespace Rugal.TokenAuth.Core.Model;

public class AuthTokens
{
    private IEnumerable<Claim> AccessTokenClaims { get; set; }
    public Guid AccessTokenId { get; set; }
    public string AccessToken { get; set; }
    public Guid RefreshTokenId { get; set; }
    public string RefreshToken { get; set; }
    public AuthTokens WithAccessTokenClaims(IEnumerable<Claim> Claims)
    {
        AccessTokenClaims = Claims;
        return this;
    }
    public IEnumerable<Claim> GetAccessTokenClaims()
    {
        return AccessTokenClaims;
    }
    public AuthTokens() { }
    public AuthTokens(IEnumerable<Claim> AccessTokenClaims)
    {
        this.AccessTokenClaims = AccessTokenClaims;
    }
}
public class TokenSetting
{
    public TokenParam TokenParam { get; set; }
    public IEnumerable<IBlackTokenVerfiy> BlackTokenVerfiys;
    public IEnumerable<IAuthVerfiy> AuthVerfiys;
    public TokenSetting(IOptions<TokenParam> ConfigOption, IEnumerable<IBlackTokenVerfiy> BlackTokenVerfiys, IEnumerable<IAuthVerfiy> AuthVerfiys)
    {
        TokenParam = ConfigOption?.Value ?? new TokenParam();

        this.BlackTokenVerfiys = BlackTokenVerfiys;
        this.AuthVerfiys = AuthVerfiys;
    }
}
public class TokenParam
{
    public string IssuerSigningKey { get; set; }
    public string AccessTokenExpires { get; set; } = "1h";
    public string RefreshTokenExpires { get; set; } = "30d";
    public string Issuer { get; set; } = "TokenAuth";
    public string Audience { get; set; } = "TokenAuth";
    public bool? ValidateIssuerSigningKey { get; set; } = true;
    public bool? ValidateIssuer { get; set; } = true;
    public bool? ValidateAudience { get; set; } = true;
    public bool? ValidateLifetime { get; set; } = true;
    public bool? RequireExpirationTime { get; set; } = true;
    public bool AuthRefreshToken { get; set; } = false;
    public string RefreshTokenHeader { get; set; } = "X-Refresh-Token";
    public string NewAccessTokenHeader { get; set; } = "X-New-Access-Token";
    public string NewRefreshTokenHeader { get; set; } = "X-New-Refresh-Token";
}
public class TokenResult
{
    public Guid TokenId { get; set; }
    public string Token { get; set; }
    public IEnumerable<Claim> Claims { get; set; }
}