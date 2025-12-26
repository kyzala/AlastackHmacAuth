using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.Sql;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddMemoryCache();
builder.Services.AddControllers();
builder.Services.AddAuthentication()
.AddHawk(options =>
{
    options.EnableServerAuthorization = true;
    options.CredentialProvider = new SqlCredentialProvider<HawkCredential, SqlConnection>(
        builder.Configuration.GetConnectionString("CredentialDbConnection")!,
        "SELECT AuthId,AuthKey,HmacAlgorithm,HashAlgorithm,User,EnableServerAuthorization,IncludeResponsePayloadHash FROM HawkCredentials WHERE AuthId = @Id");
})
.AddHmac(options =>
{
    options.CredentialProvider = new SqlCredentialProvider<HmacCredential, SqlConnection>(
        builder.Configuration.GetConnectionString("CredentialDbConnection")!,
        "SELECT AppId,AppKey,HmacAlgorithm,HashAlgorithm FROM HmacCredentials WHERE AppId = @Id");
});

var app = builder.Build();

app.UseAuthentication();
app.UseHawkServerAuthorization();
app.UseAuthorization();
app.MapControllers();
app.Run();