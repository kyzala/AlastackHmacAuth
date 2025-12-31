using Alastack.HmacAuth;
using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.Credentials;
using ApiHostSample.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

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
            options.ForwardIndex = 4; // ApiProxy Forward
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
            options.ForwardIndex = 4; // ApiProxy Forward
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

        app.UseAuthentication();
        app.UseHawkServerAuthorization();
        app.UseAuthorization();
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