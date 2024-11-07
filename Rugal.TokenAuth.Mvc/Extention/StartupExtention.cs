using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rugal.TokenAuth.Core.Extention;
using Rugal.TokenAuth.Mvc.Model;

namespace Rugal.TokenAuth.Mvc.Extention;

public static class StartupExtention
{
    public static IHostApplicationBuilder AddTokenAuth_Mvc(this IHostApplicationBuilder Builder)
    {
        var Setting = new TokenAuthMvcSetting();
        Builder.Configuration.GetSection("TokenAuth:Mvc")?.Bind(Setting);

        Builder.AddTokenAuth_Core()
            .Services
            .AddSingleton(Setting);

        return Builder;
    }
}
