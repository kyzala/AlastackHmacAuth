using Alastack.HmacAuth;
using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.Credentials;
using ApiHostSample.Models;
using Microsoft.EntityFrameworkCore;

namespace ApiHostSample
{
    public class Program
    {
        public static void Main(string[] args)
        {
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
            })
            .AddHawk(options =>
            {
                var credential = new HawkCredential
                {
                    AuthId = "id123",
                    AuthKey = "3@uo45er?",
                    EnableServerAuthorization = true,
                    IncludeResponsePayloadHash = true,
                };
                options.ForwardIndex = 4; // ApiProxy Forward
                options.EnableServerAuthorization = true;
                var dict = new Dictionary<string, HawkCredential> { { "id123", credential } };
                options.CredentialProvider = new MemoryCredentialProvider<HawkCredential>(dict);
                options.Events.OnSetSpecificData = context => { context.Data = "specific data"; return Task.CompletedTask; };
            })
            .AddHmac(options =>
            {
                var credential = new HmacCredential
                {
                    AppId = "id123",
                    AppKey = "3@uo45er?"
                };
                options.ForwardIndex = 4; // ApiProxy Forward
                var dict = new Dictionary<string, HmacCredential> { { "id123", credential } };
                options.CredentialProvider = new MemoryCredentialProvider<HmacCredential>(dict);
            });

            //builder.Services.AddAuthorization(options => 
            //{
            //    options.AddPolicy("HawkPolicy", builder => 
            //    {
            //        builder.AuthenticationSchemes.Add("Hawk");
            //        builder.RequireAuthenticatedUser();
            //    });
            //});

            var app = builder.Build();

            app.UseAuthentication();
            app.UseHawkServerAuthorization();
            app.UseAuthorization();
            app.MapControllers();
            app.Run();
        }
    }
}