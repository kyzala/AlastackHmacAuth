using Alastack.HmacAuth;
using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.Credentials;
using ApiHostSample.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using System.Net;

namespace ApiHostSample;

public class Program
{

    public static void Main(string[] args)
    {
        string appId = "id123";
        string appKey = "3@uo45er?";

        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddMemoryCache();
        builder.Services.AddControllers();
        builder.Services.AddDbContext<TodoContext>(opt => opt.UseInMemoryDatabase("TodoList"));

        
        builder.Services.AddAuthentication(options =>
        {
            //options.DefaultScheme = HawkDefaults.AuthenticationScheme;

            //options.DefaultAuthenticateScheme = HawkDefaults.AuthenticationScheme;
            //options.DefaultChallengeScheme = HawkDefaults.AuthenticationScheme;

            //options.DefaultAuthenticateScheme = HmacDefaults.AuthenticationScheme;
            //options.DefaultChallengeScheme = HmacDefaults.AuthenticationScheme;
            options.DefaultAuthenticateScheme = "HmacOrHawk";
            options.DefaultChallengeScheme = "HmacOrHawk";


        })
        .AddPolicyScheme("HmacOrHawk", "HmacOrHawk", options =>
        {
            options.ForwardDefaultSelector = context =>
            {
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                if (authHeader?.StartsWith("Hmac ") == true)
                    return "Hmac";
                if (authHeader?.StartsWith("Hawk ") == true)
                    return "Hawk";
                return null; // Return the default challenge scheme
            };
        })
        .AddHawk(options =>
        {
            var credential = new HawkCredential
            {
                AuthId = appId,
                AuthKey = appKey,
                EnableServerAuthorization = true,
                IncludeResponsePayloadHash = true,
            };
            options.EnableServerAuthorization = true;
            var dict = new Dictionary<string, HawkCredential> { { appId, credential } };
            options.CredentialProvider = new MemoryCredentialProvider<HawkCredential>(dict);
            options.Events.OnSetSpecificData = context => { context.Data = "specific data"; return Task.CompletedTask; };
        })
        .AddHmac(options =>
        {
            var credential = new HmacCredential
            {
                AppId = appId,
                AppKey = appKey
            };
            var dict = new Dictionary<string, HmacCredential> { { appId, credential } };
            options.CredentialProvider = new MemoryCredentialProvider<HmacCredential>(dict);
        });

        //builder.Services.AddAuthorization(options =>
        //{
        //    //options.AddPolicy(HawkOrHmacPolicy.PolicyName, builder =>
        //    //{
        //    //    builder.AddAuthenticationSchemes("Hmac", "Hawk")
        //    //    .RequireAuthenticatedUser();
        //    //});
        //    options.AddPolicy(HawkOrHmacPolicy.PolicyName, HawkOrHmacPolicy.Build());
        //});

        var app = builder.Build();

        // ApiProxy Forward: rewrite Request.Host/Scheme from X-Forwarded-* headers.
        // ForwardLimit must cover the number of proxies in the chain.
        // KnownProxies declares the trusted proxy machines (dev: 192.168.1.102 / 192.168.1.103);
        // X-Forwarded-* headers from untrusted sources are ignored.
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto,
            ForwardLimit = 5
        };
        //forwardedHeadersOptions.KnownProxies.Add(IPAddress.Loopback);        // 127.0.0.1
        //forwardedHeadersOptions.KnownProxies.Add(IPAddress.IPv6Loopback);    // ::1
        forwardedHeadersOptions.KnownProxies.Add(IPAddress.Parse("192.168.1.102"));
        forwardedHeadersOptions.KnownProxies.Add(IPAddress.Parse("192.168.1.103"));
        //forwardedHeadersOptions.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.Parse("192.168.1.0"), 24));
        app.UseForwardedHeaders(forwardedHeadersOptions);

        app.UseAuthentication();
        app.UseHawkServerAuthorization();
        app.UseAuthorization();

        app.MapGet("/debug-forwarded", (HttpContext ctx) => Results.Json(new
        {
            RequestHost = ctx.Request.Host.ToString(),
            RequestScheme = ctx.Request.Scheme,
            RemoteIp = ctx.Connection.RemoteIpAddress?.ToString(),
            AllHeaders = ctx.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString())
        }))
            .RequireAuthorization(new AuthorizeAttribute
            {
                AuthenticationSchemes = "HmacOrHawk"
            });

        app.MapControllers();
        app.Run();
    }
}

//public class HawkOrHmacPolicy
//{
//    public const string PolicyName = "HmacOrHawk";

//    public static AuthorizationPolicy Build()
//    {
//        return new AuthorizationPolicyBuilder()
//            .AddAuthenticationSchemes("Hawk", "Hmac")
//            .RequireAuthenticatedUser()
//            .Build();
//    }
//}