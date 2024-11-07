using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Rugal.TokenAuth.Core.Interface;
using Rugal.TokenAuth.Core.Model;
using Rugal.TokenAuth.Core.Service;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace Rugal.TokenAuth.Core.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class JwtAuthAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var HttpContext = context.HttpContext;
        var Provider = HttpContext.RequestServices;

        var DefaultUnAuthResult = new UnauthorizedResult();
        var Token = HttpContext.Request.Headers.Authorization.FirstOrDefault();

        if (string.IsNullOrWhiteSpace(Token) || !Regex.IsMatch(Token, "^Bearer"))
        {
            context.Result = DefaultUnAuthResult;
            return;
        }

        Token = Regex.Replace(Token, "^Bearer", "").TrimStart().TrimEnd();
        string RefreshToken = null;

        var TokenService = Provider.GetService<TokenService>();
        var TokenParam = TokenService.TokenParam;

        var AccessTokenVerify = TokenService.VerifyAll(Token, out var Claims);
        if (!AccessTokenVerify)
        {
            if (!TokenParam.AuthRefreshToken)
            {
                context.Result = DefaultUnAuthResult;
                return;
            }

            RefreshToken = HttpContext.Request.Headers[TokenParam.RefreshTokenHeader];
            if (string.IsNullOrWhiteSpace(RefreshToken))
            {
                context.Result = DefaultUnAuthResult;
                return;
            }

            var Tokens = TokenService.RefreshTokens(RefreshToken);
            HttpContext.Response.Headers[TokenParam.NewAccessTokenHeader] = Tokens.AccessToken;
            HttpContext.Response.Headers[TokenParam.NewRefreshTokenHeader] = Tokens.RefreshToken;

            Token = Tokens.AccessToken;
            Claims = Tokens.GetAccessTokenClaims();
        }

        var AllUserInfo = Provider.GetServices<IUserInfo>();
        foreach (var UserInfo in AllUserInfo)
        {
            UserInfo.AccessToken = Token;
            UserInfo.RefreshToken = RefreshToken;
            UserInfo.SetClaims(Claims);
        }
        HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(Claims));
    }
}