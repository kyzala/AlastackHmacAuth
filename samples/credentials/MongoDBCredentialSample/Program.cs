using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.MongoDB;
using StackExchange.Redis;

// mongodb://localhost:27017?appname=authsample&directConnection=true&serverSelectionTimeoutMS=2000
// mongodb://authreader:Password@localhost:27017?appname=authsample&directConnection=true&serverSelectionTimeoutMS=2000&authSource=credentialdb

var builder = WebApplication.CreateBuilder(args);
//builder.Services.AddMemoryCache();
builder.Services.AddStackExchangeRedisCache(options =>
{
    //options.Configuration = builder.Configuration.GetConnectionString("MyRedisConStr");
    //options.InstanceName = "SampleInstance";
    options.ConfigurationOptions = new ConfigurationOptions();
    options.ConfigurationOptions.EndPoints.Add("192.168.1.111", 6379);
    options.ConfigurationOptions.Password = "0OZUTBfsU9";
    options.ConfigurationOptions.ConnectRetry = 5;
    options.ConfigurationOptions.DefaultDatabase = 0;
});
builder.Services.AddControllers();
builder.Services.AddAuthentication()
.AddHawk(options =>
{
    options.CredentialProvider = new MongoDBCredentialProvider<HawkCredential>(
        //"mongodb://localhost:27017?appname=authsample&directConnection=true&serverSelectionTimeoutMS=2000",
        "mongodb://root:Pass1234@192.168.1.113:30017?appname=authsample&directConnection=true&serverSelectionTimeoutMS=2000&authSource=admin&authMechanism=SCRAM-SHA-256",
        "credentialdb",
        "hawk",
        "authId");
})
.AddHmac(options =>
{
    options.CredentialProvider = new MongoDBCredentialProvider<HmacCredential>(
        //"mongodb://localhost:27017?appname=authsample&directConnection=true&serverSelectionTimeoutMS=2000",
        "mongodb://root:Pass1234@192.168.1.113:30017?appname=authsample&directConnection=true&serverSelectionTimeoutMS=2000&authSource=admin&authMechanism=SCRAM-SHA-256",
        "credentialdb", 
        "hmac",
        "appId");
});
//mongodb://authUser:Test2022@localhost:27017/credentials
var app = builder.Build();

app.UseAuthentication();
app.UseHawkServerAuthorization();
app.UseAuthorization();
app.MapControllers();
app.Run();