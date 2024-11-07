using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using Rugal.TokenAuth.Core.Interface;
using Rugal.TokenAuth.Core.Model;
using Rugal.TokenAuth.Core.Service;
using System.Reflection;

namespace Rugal.TokenAuth.Core.Extention;

public static class StartupExtention
{
    public static IHostApplicationBuilder AddTokenAuth_Core(this IHostApplicationBuilder Builder)
    {
        Builder.Services
            .AddSingleton<TokenSetting>()
            .AddScoped<TokenService>()
            .Configure<TokenParam>(Builder.Configuration.GetSection("TokenAuth:Token"));

        return Builder;
    }
    public static IHostApplicationBuilder AddTokenAuth<TUserQueryer>(this IHostApplicationBuilder Builder)
        where TUserQueryer : class, IUserQueryer
    {
        Builder.Services
            .AddSingleton<ArgonService>()
            .AddSingleton<TokenSetting>()
            .AddScoped<TokenService>()
            .AddScoped<IUserQueryer, TUserQueryer>()
            .Configure<ArgonSetting>(Builder.Configuration.GetSection("TokenAuth:Argon"))
            .Configure<TokenParam>(Builder.Configuration.GetSection("TokenAuth:Token"))
            .Configure<SecurePolicySetting>(Builder.Configuration.GetSection("TokenAuth:SecurePolicy"));

        return Builder;
    }
    public static IHostApplicationBuilder AddTokenAuth<TAuthService, TUserQueryer>(this IHostApplicationBuilder Builder)
        where TUserQueryer : class, IUserQueryer
        where TAuthService : class
    {
        Builder.AddTokenAuth<TUserQueryer>();
        Builder.Services.AddScoped<TAuthService>();
        return Builder;
    }
    public static IHostApplicationBuilder AddTokenAuth_UserInfo<TUserInfo>(this IHostApplicationBuilder Builder)
        where TUserInfo : class, IUserInfo
    {
        Builder.Services.AddScoped<IUserInfo, TUserInfo>();
        Builder.Services.AddScoped(Provider =>
        {
            var GetUserInfo = Provider
                .GetServices<IUserInfo>()
                .FirstOrDefault(Item => Item.GetType() == typeof(TUserInfo)) as TUserInfo;

            return GetUserInfo;
        });
        return Builder;
    }

    public static IServiceCollection AddTokenAuth_BlackVerify<TService>(this IServiceCollection Services)
        where TService : class, IBlackTokenVerfiy
    {
        Services.AddScoped<TService>();
        return Services;
    }
    public static IServiceCollection AddTokenAuth_AuthVerify<TService>(this IServiceCollection Services)
        where TService : class, IAuthVerfiy
    {
        Services.AddScoped<TService>();
        return Services;
    }
    public static IServiceCollection AddSwaggerToken(this IServiceCollection Services)
    {
        Services.AddSwaggerGen(Options =>
        {
            Options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
            {
                Name = "Authorization",
                Scheme = "Bearer",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                BearerFormat = "JWT",
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            });
            Options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Id = "Bearer",
                            Type = ReferenceType.SecurityScheme,
                        }
                    },
                    Array.Empty<string>()
                }
            });
            var XmlFile = $"{Assembly.GetEntryAssembly().GetName().Name}.xml";
            var XmlPath = Path.Combine(AppContext.BaseDirectory, XmlFile);
            Options.IncludeXmlComments(XmlPath);
        });
        return Services;
    }
}