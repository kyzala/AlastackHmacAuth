using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.LiteDB;

Console.WriteLine(Environment.Version);

const string SeedArgs = "/seed";
bool seed = true;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddMemoryCache();
builder.Services.AddControllers();
builder.Services.AddAuthentication()
.AddHawk(options =>
{
    var connectionString = "Filename=Data\\hawk.db;Password=1234";
    var collectionName = "hawk";
    var keyName = "authId";
    var credential = new HawkCredential
    {
        AuthId = "id123",
        AuthKey = "3@uo45er?",
        EnableServerAuthorization = true,
        IncludeResponsePayloadHash = true,
    };
    var provider = new LiteDBCredentialProvider<HawkCredential>(connectionString, collectionName, keyName);
    // Init seed data.
    if (seed || args.Any(x => x == SeedArgs))
    {
        provider.InitDatabase(true);
        provider.AddCredential(credential);
    }
    options.CredentialProvider = provider;
})
.AddHmac(options =>
{
    var connectionString = "Filename=Data\\hmac.db;Password=1234";
    var collectionName = "hmac";
    var keyName = "appId";
    var credential = new HmacCredential
    {
        AppId = "id123",
        AppKey = "3@uo45er?"
    };
    var provider = new LiteDBCredentialProvider<HmacCredential>(connectionString, collectionName, keyName);
    // Init seed data.
    if (seed || args.Any(x => x == SeedArgs))
    {
        provider.InitDatabase(true);
        provider.AddCredential(credential);
    }
    options.CredentialProvider = provider;
});
var app = builder.Build();

app.UseAuthentication();
app.UseHawkServerAuthorization();
app.UseAuthorization();
app.MapControllers();
app.Run();
