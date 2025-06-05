using AuthorizationServer.Helpers;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthorizationServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var env = builder.Environment;

            // Add services to the container.
            builder.Services.AddControllersWithViews();

            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.LoginPath = "/account/login";
                });

            builder.Services.AddDbContext<DbContext>(options =>
            {
                // Configure the context to use an in-memory store.
                options.UseInMemoryDatabase(nameof(DbContext));

                // Register the entity sets needed by OpenIddict.
                options.UseOpenIddict();
            });

            builder.Services.AddOpenIddict()
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the EF Core stores/models.
                    options.UseEntityFrameworkCore()
                        .UseDbContext<DbContext>();
                })
                .AddServer(options =>
                {
                    options.AllowClientCredentialsFlow();

                    options.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();

                    options.AllowRefreshTokenFlow();

                    options.SetAuthorizationEndpointUris("/connect/authorize")
                           .SetTokenEndpointUris("/connect/token")
                           .SetUserInfoEndpointUris("/connect/userinfo")
                           .SetRevocationEndpointUris("/connect/revocation");

                    options.AddEphemeralEncryptionKey();
                    //       .AddEphemeralSigningKey()

                    // In prod please use X509Certificate2 pfx file instead
                    var keyPath = Path.Combine(builder.Environment.ContentRootPath, "Keys", "private.key");
                    options.AddSigningKey(new RsaSecurityKey(RsaHelpers.LoadRsaPrivateKey(keyPath))
                    {
                        KeyId = "my-rsa-key"
                    });

                    options.DisableAccessTokenEncryption();

                    // Register scopes (permissions)
                    options.RegisterScopes("api");

                    // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                    options
                        .UseAspNetCore()
                        .EnableTokenEndpointPassthrough()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableUserInfoEndpointPassthrough();
                });

            builder.Services.AddHostedService<TestData>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            // Necessary for using cookies auth and openiddict auth
            app.UseAuthentication();

            // Necessary for checking the access token to access resources
            app.UseAuthorization();

            app.MapDefaultControllerRoute();

            app.Run();
        }
    }
}
