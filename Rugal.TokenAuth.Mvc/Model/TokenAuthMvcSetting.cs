namespace Rugal.TokenAuth.Mvc.Model;

public class TokenAuthMvcSetting
{
    public string UnAuthUrl { get; set; } = "/";
    public string AccessTokenKey { get; set; } = "AccessToken";
    public string RefreshTokenKey { get; set; } = "RefreshToken";
}
