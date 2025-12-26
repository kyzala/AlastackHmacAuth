using Alastack.HmacAuth.EntityFrameworkCore;
using Alastack.HmacAuth.AspNetCore;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddMemoryCache();
builder.Services.AddControllers();
builder.Services.AddAuthentication()
.AddHawk(options =>
{ 
    options.EnableServerAuthorization = true;
    var optionsBuilder = new DbContextOptionsBuilder<CredentialContext<HawkCredential>>();
    optionsBuilder.UseSqlServer(builder.Configuration.GetConnectionString("CredentialDbConnection"), b => b.MaxBatchSize(100));
    options.CredentialProvider = new EFCoreCredentialProvider<HawkCredential>(optionsBuilder, "HawkCredentials", "AuthId");
})
.AddHmac(options =>
{
    var optionsBuilder = new DbContextOptionsBuilder<CredentialContext<HmacCredential>>();
    optionsBuilder.UseSqlServer(builder.Configuration.GetConnectionString("CredentialDbConnection"), b => b.MaxBatchSize(100));
    options.CredentialProvider = new EFCoreCredentialProvider<HmacCredential>(optionsBuilder, "HmacCredentials", "AppId");
});

var app = builder.Build();

app.UseAuthentication();
app.UseHawkServerAuthorization();
app.UseAuthorization();
app.MapControllers();
app.Run();