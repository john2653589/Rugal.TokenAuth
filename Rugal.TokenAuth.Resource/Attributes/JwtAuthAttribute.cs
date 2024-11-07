using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Rugal.TokenAuth.Core.Interface;
using Rugal.TokenAuth.Core.Service;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace Rugal.TokenAuth.Server.Resource.Attributes;

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
        var TokenService = Provider.GetService<TokenService>();
        if (!TokenService.VerifyAll(Token, out var Claims))
        {
            context.Result = DefaultUnAuthResult;
            return;
        }

        var AllUserInfo = Provider.GetServices<IUserInfo>();
        foreach (var UserInfo in AllUserInfo)
        {
            UserInfo.Token = Token;
            UserInfo.SetClaims(Claims);
        }
        HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(Claims));
    }
}