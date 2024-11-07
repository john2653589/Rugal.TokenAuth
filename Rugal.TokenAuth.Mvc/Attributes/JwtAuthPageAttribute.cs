using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Rugal.TokenAuth.Core.Interface;
using Rugal.TokenAuth.Core.Service;
using Rugal.TokenAuth.Mvc.Model;
using System.Security.Claims;

namespace Rugal.TokenAuth.Core.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class JwtAuthPageAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var HttpContext = context.HttpContext;
        var Provider = HttpContext.RequestServices;

        var Setting = Provider.GetService<TokenAuthMvcSetting>();
        var DefaultUnAuthResult = new RedirectResult(Setting.UnAuthUrl);
        var Cookies = HttpContext.Request.Cookies;
        var AccessToken = Cookies[Setting.AccessTokenKey];
        var RefreshToken = Cookies[Setting.RefreshTokenKey];

        if (string.IsNullOrWhiteSpace(AccessToken))
        {
            context.Result = DefaultUnAuthResult;
            return;
        }

        var TokenService = Provider.GetService<TokenService>();
        var AccessTokenVerify = TokenService.VerifyAll(AccessToken, out var Claims);
        if (!AccessTokenVerify)
        {
            context.Result = DefaultUnAuthResult;
            return;
        }
        var Option = new CookieOptions()
        {
            HttpOnly = true,
            Secure = true,
            Domain = HttpContext.Request.Host.Host,
            SameSite = SameSiteMode.Strict,
        };

        HttpContext.Response.Cookies.Delete(Setting.AccessTokenKey);
        HttpContext.Response.Cookies.Delete(Setting.RefreshTokenKey);

        HttpContext.Response.Cookies.Append(Setting.AccessTokenKey, AccessToken, Option);
        HttpContext.Response.Cookies.Append(Setting.RefreshTokenKey, RefreshToken, Option);

        var AllUserInfo = Provider.GetServices<IUserInfo>();
        foreach (var UserInfo in AllUserInfo)
        {
            UserInfo.AccessToken = AccessToken;
            UserInfo.RefreshToken = RefreshToken;
            UserInfo.SetClaims(Claims);
        }
        HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(Claims));
    }
}