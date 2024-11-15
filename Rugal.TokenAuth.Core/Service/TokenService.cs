using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Rugal.DotNetLib.Core.TimeConvert;
using Rugal.TokenAuth.Core.Interface;
using Rugal.TokenAuth.Core.Model;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Rugal.TokenAuth.Core.Service;

public partial class TokenService
{
    public readonly TokenSetting Setting;
    public IEnumerable<IBlackTokenVerfiy> BlackTokenVerfiys => Setting.BlackTokenVerfiys;
    public IEnumerable<IAuthVerfiy> AuthVerfiys => Setting.AuthVerfiys;
    public TokenParam TokenParam => Setting.TokenParam;
    public readonly IServiceProvider Provider;
    public TokenService(TokenSetting Setting, IServiceProvider Provider)
    {
        this.Setting = Setting;
        this.Provider = Provider;
    }
    public AuthTokens GenerateAuthTokens(Guid UserId, Dictionary<string, object> Claims)
    {
        var AccessToken = GenerateAccessToken(UserId, Claims);
        var RefreshToken = GenerateRefreshToken(UserId);
        var Result = new AuthTokens(AccessToken.Claims)
        {
            AccessTokenId = AccessToken.TokenId,
            AccessToken = AccessToken.Token,
            RefreshTokenId = RefreshToken.TokenId,
            RefreshToken = RefreshToken.Token,
        };
        return Result;
    }
    public TokenResult GenerateAccessToken(Guid UserId, Dictionary<string, object> Claims)
    {
        var CreateClaims = GenerateBaseClaims(UserId);
        if (Claims is not null)
        {
            foreach (var Item in Claims)
                CreateClaims.TryAdd(Item.Key, Item.Value);
        }
        var ExpireTime = TokenParam.AccessTokenExpires.ParseTimeString();
        var Token = GenerateToken(CreateClaims, ExpireTime);
        return Token;
    }
    public TokenResult GenerateRefreshToken(Guid UserId)
    {
        var CreateClaims = GenerateBaseClaims(UserId);
        var ExpireTime = TokenParam.RefreshTokenExpires.ParseTimeString();
        var Token = GenerateToken(CreateClaims, ExpireTime);
        return Token;
    }
    public AuthTokens RefreshTokens(string RefreshToken)
    {
        if (!ValidateToken(RefreshToken, out var AccessClaims))
            return null;

        var GetUserId = AccessClaims
            .FirstOrDefault(Item => Item.Type == "sub")?
            .Value;

        if (string.IsNullOrWhiteSpace(GetUserId))
            return null;

        var UserId = Guid.Parse(GetUserId);
        var Result = RefreshTokens(UserId);
        return Result;
    }
    public AuthTokens RefreshTokens(Guid UserId)
    {
        var UserQueryer = Provider.GetService<IUserQueryer>();
        if (!UserQueryer.QueryUserClaims(UserId, out var Claims, out var Message))
            return null;

        var AccessToken = GenerateAccessToken(UserId, Claims);
        var NewRefreshToken = GenerateRefreshToken(UserId);
        var Result = new AuthTokens(AccessToken.Claims)
        {
            AccessTokenId = AccessToken.TokenId,
            AccessToken = AccessToken.Token,
            RefreshTokenId = NewRefreshToken.TokenId,
            RefreshToken = NewRefreshToken.Token,
        };
        return Result;
    }
    public bool ValidateToken(string Token, out IEnumerable<Claim> Claims)
    {
        Claims = null;
        if (string.IsNullOrWhiteSpace(Token))
            return false;

        if (Token.Contains(' '))
            Token = Token.Split(' ').Last();

        var SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TokenParam.IssuerSigningKey));
        try
        {
            var ValidatParame = new TokenValidationParameters
            {
                IssuerSigningKey = SigningKey,
                ValidIssuer = TokenParam.Issuer,
                ValidAudience = TokenParam.Audience,

                ValidateIssuerSigningKey = TokenParam.ValidateIssuerSigningKey ?? true,
                ValidateIssuer = TokenParam.ValidateIssuer ?? true,
                ValidateAudience = TokenParam.ValidateAudience ?? true,
                ValidateLifetime = TokenParam.ValidateLifetime ?? true,
                RequireExpirationTime = TokenParam.RequireExpirationTime ?? true,
                LifetimeValidator = (notBefore, expires, securityToken, validationParameters) =>
                {
                    var TokenSet = securityToken as JwtSecurityToken;
                    var Exp = TokenSet.Claims.First(Item => Item.Type == "exp").Value;
                    if (long.TryParse(Exp, out var Time))
                    {
                        var ExpTime = DateTimeOffset.FromUnixTimeSeconds(Time).LocalDateTime;
                        return DateTime.Now < ExpTime;
                    }
                    return false;
                }
            };
            var TokenHandler = new JwtSecurityTokenHandler();
            var TokenValidate = TokenHandler.ValidateToken(Token, ValidatParame, out SecurityToken ValidatedToken);
            var DeToken = ValidatedToken as JwtSecurityToken;
            Claims = DeToken?.Claims;
            if (Claims == null)
                return false;

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            return false;
        }
    }
    public bool VerifyBlackToken(string Token, IEnumerable<Claim> Claims)
    {
        if (BlackTokenVerfiys is null || !BlackTokenVerfiys.Any())
            return true;

        foreach (var Service in BlackTokenVerfiys)
        {
            var IsVerify = Service.VerifyBlackToken(Token, Claims);
            if (!IsVerify)
                return false;
        }
        return true;
    }
    public bool VerifyAuth(string Token, IEnumerable<Claim> Claims)
    {
        if (AuthVerfiys is null || !AuthVerfiys.Any())
            return true;

        foreach (var Service in AuthVerfiys)
        {
            var IsVerify = Service.VerifyAuth(Token, Claims);
            if (!IsVerify)
                return false;
        }
        return true;
    }
    public bool VerifyAll(string Token, out IEnumerable<Claim> Claims)
    {
        Claims = null;
        if (string.IsNullOrWhiteSpace(Token))
            return false;

        if (!ValidateToken(Token, out Claims))
            return false;

        if (!VerifyBlackToken(Token, Claims))
            return false;

        if (!VerifyAuth(Token, Claims))
            return false;

        return true;
    }
    public virtual TokenResult GenerateToken(Dictionary<string, object> Claims, TimeSpan ExpireTime)
    {
        var SigningKeyValue = TokenParam.IssuerSigningKey;
        var SigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningKeyValue));
        var SignCred = new SigningCredentials(SigningKey, SecurityAlgorithms.HmacSha256);
        var NowTime = DateTime.Now;
        var Expires = NowTime.Add(ExpireTime);
        var TokenId = Guid.NewGuid();
        Claims.Remove("jti");
        Claims.Add("jti", TokenId);

        var JwtDescrip = new SecurityTokenDescriptor()
        {
            Issuer = TokenParam.Issuer,
            Audience = TokenParam.Audience,
            Claims = Claims,
            NotBefore = NowTime,
            Expires = Expires,
            SigningCredentials = SignCred,
            IssuedAt = NowTime,
        };
        var TokenCreater = new JwtSecurityTokenHandler();
        var SecurityToken = TokenCreater.CreateJwtSecurityToken(JwtDescrip);
        var Token = TokenCreater.WriteToken(SecurityToken);

        return new TokenResult()
        {
            TokenId = TokenId,
            Token = Token,
            Claims = SecurityToken.Claims,
        };
    }
    protected virtual Dictionary<string, object> GenerateBaseClaims(Guid UserId)
    {
        return new Dictionary<string, object>()
        {
            { "sub", UserId },
        };
    }
}