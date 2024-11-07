using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using System.Reflection;

namespace Rugal.TokenAuth.Server.Resource.Extention
{
    public static class StartupExtention
    {
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
}