# Alastack.HmacAuth

Hmac and [Hawk](https://github.com/mozilla/hawk) authentication for .NET. Clients sign every request with a shared key; servers verify identity, request integrity (method, path, query, host, payload) and replay protection (timestamp + nonce).

This README is shared by all packages in the family — install only the ones you need.

- **Alastack.HmacAuth** — client `DelegatingHandler`s: `HmacDelegatingHandler`, `HawkDelegatingHandler`.
- **Alastack.HmacAuth.AspNetCore** — server `AuthenticationHandler`s, Hawk middleware and replay protection.
- **Alastack.HmacAuth.Sql** — `ICredentialProvider<T>` backed by any ADO.NET database (Dapper).
- **Alastack.HmacAuth.MongoDB** — `ICredentialProvider<T>` backed by MongoDB.
- **Alastack.HmacAuth.LiteDB** — `ICredentialProvider<T>` backed by LiteDB.
- **Alastack.HmacAuth.EFCore** — `ICredentialProvider<T>` backed by Entity Framework Core.

```powershell
dotnet add package Alastack.HmacAuth            # client
dotnet add package Alastack.HmacAuth.AspNetCore # server
```

Source, samples and issues: https://github.com/kyzala/AlastackHmacAuth

## Client

```csharp
using Alastack.HmacAuth;

var client = new HttpClient(new HmacDelegatingHandler("appId", "appKey"))
{
    BaseAddress = new Uri("https://api.example.com/")
};

var hawkClient = new HttpClient(new HawkDelegatingHandler("authId", "authKey"));
```

With `IHttpClientFactory`:

```csharp
services.AddHttpClient("api", c => c.BaseAddress = new Uri("https://api.example.com/"))
        .AddHttpMessageHandler(_ => new HmacDelegatingHandler("appId", "appKey"));
```

Hawk can also verify the server response when the server enables server authorization:

```csharp
var handler = new HawkDelegatingHandler(new HawkSettings
{
    AuthId = "authId",
    AuthKey = "authKey",
    EnableServerAuthorizationValidation = true, // verify Server-Authorization
    EnableServerTimeValidation = true           // verify tsm, then adjust TimeOffset
});
```

The Hmac `Authorization` header is `Hmac {appId}:{timestamp}:{nonce}:{signature}:{payloadHash}`. Both handlers accept a settings object (`HmacSettings` / `HawkSettings`); the important ones are the id/key pair, `HashAlgorithm` (default `SHA256`, must match the server), `IncludePayloadHash` (default `true`) and `TimeOffset` (**seconds**) for a skewed clock.

## Server

```csharp
builder.Services.AddAuthentication()
    .AddHmac(options =>
    {
        options.CredentialProvider = new MemoryCredentialProvider<HmacCredential>(
            new Dictionary<string, HmacCredential>
            {
                ["appId1"] = new HmacCredential { AppId = "appId1", AppKey = "appKey1" }
            });
    })
    .AddHawk(options =>
    {
        options.CredentialProvider = new MemoryCredentialProvider<HawkCredential>(
            new Dictionary<string, HawkCredential>
            {
                ["authId1"] = new HawkCredential { AuthId = "authId1", AuthKey = "authKey1" }
            });
    });

var app = builder.Build();

app.UseAuthentication();
app.UseHawkServerAuthorization(); // only for Hawk response signing; after UseAuthentication
app.UseAuthorization();
```

Then protect endpoints with the scheme: `[Authorize(AuthenticationSchemes = "Hmac")]` (or `"Hawk"`).

Replay protection is on by default: a nonce is remembered for `MaxReplayRequestAge` (60 s) and clock skew is limited to `TimeSkew` (300 s). `CredentialCacheTime` (300 s, `0` disables caching) controls credential caching, `TimeOffset` (**milliseconds**) corrects the server clock, and `DisableChallenge` (`true`) suppresses `WWW-Authenticate` responses on failure.

## Credential stores

Assign any `ICredentialProvider<TCredential>` to `HmacOptions.CredentialProvider` / `HawkOptions.CredentialProvider`. SQL works with any `IDbConnection`, and the query must return the credential columns:

```csharp
options.CredentialProvider = new SqlCredentialProvider<HmacCredential, SqlConnection>(
    connectionString,
    "SELECT AppId, AppKey, HmacAlgorithm, HashAlgorithm FROM HmacCredentials WHERE AppId = @Id");
```

```csharp
// MongoDB: connection string, database, collection, id field
options.CredentialProvider = new MongoDBCredentialProvider<HmacCredential>(
    "mongodb://localhost:27017", "credentialdb", "hmac", "appId");

// LiteDB: file connection string, collection, id field
options.CredentialProvider = new LiteDBCredentialProvider<HmacCredential>(
    "Filename=Data\\hmac.db;Password=1234", "hmac", "appId");

// EF Core: reuse your DbContext options, then the table and key column
var builder = new DbContextOptionsBuilder<CredentialContext<HmacCredential>>();
builder.UseSqlServer(connectionString);
options.CredentialProvider = new EFCoreCredentialProvider<HmacCredential>(builder, "HmacCredentials", "AppId");
```

The storage-specific providers also expose helpers such as `InitDatabase()` and `AddCredential()` for seeding.

## Behind a reverse proxy

The host and port are part of the signature. `DefaultHostResolver` reads the **leftmost** `X-Forwarded-Host` entry, so the original client host is used even through multiple proxies; if other code needs `Request.Host`/`Request.Scheme`, register the middleware and trust only your proxies:

```csharp
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto,
    ForwardLimit = 5,
    KnownProxies = { IPAddress.Parse("192.168.1.102"), IPAddress.Parse("192.168.1.103") }
});
```

Use `KnownIPNetworks` with `System.Net.IPNetwork` to trust a subnet (`KnownNetworks` is obsolete since .NET 8). Never trust arbitrary proxies while the app is reachable directly — a forged `X-Forwarded-Host` would change `Request.Host`.

## Upgrading to 2.3.0

- Default `HashAlgorithm` changed from `MD5` to `SHA256`. Upgrade client and server together, or set `HashAlgorithm = "MD5"` explicitly.
- `IHostResolver.Resolve` is now `Resolve(HttpRequest request)`; `ForwardIndex` was removed from `HmacOptions` and `HawkOptions`.
- MAC/signature comparisons are now constant-time.

## Samples

Runnable examples for clients, servers, every credential store and a YARP proxy topology:
https://github.com/kyzala/AlastackHmacAuth/tree/main/samples

