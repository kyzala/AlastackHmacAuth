# Alastack.HmacAuth.AspNetCore

ASP.NET Core authentication handlers for **Hmac** and **Hawk** request signing. Clients sign each request with a shared key; the server verifies identity, request integrity (method, path, query, host, payload) and protects against replay via timestamp + nonce validation.

Client package: [Alastack.HmacAuth](https://www.nuget.org/packages/Alastack.HmacAuth) · Source & samples: https://github.com/kyzala/AlastackHmacAuth

## Installation

```powershell
dotnet add package Alastack.HmacAuth.AspNetCore
```

## Quick start — Hmac

```csharp
using Alastack.HmacAuth.AspNetCore;
using Alastack.HmacAuth.Credentials;

builder.Services.AddAuthentication()
    .AddHmac(options =>
    {
        options.CredentialProvider = new MemoryCredentialProvider<HmacCredential>(
            new Dictionary<string, HmacCredential>
            {
                ["appId1"] = new HmacCredential { AppId = "appId1", AppKey = "appKey1" }
            });
    });

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
```

Protect endpoints with the `Hmac` scheme:

```csharp
[Authorize(AuthenticationSchemes = "Hmac")]
[ApiController]
public class TodoItemsController : ControllerBase { ... }
```

## Quick start — Hawk

```csharp
builder.Services.AddAuthentication()
    .AddHawk(options =>
    {
        options.CredentialProvider = new MemoryCredentialProvider<HawkCredential>(
            new Dictionary<string, HawkCredential>
            {
                ["id1"] = new HawkCredential { Id = "id1", Key = "key1" }
            });
    });
```

### Hawk server authorization (response signing)

To let clients verify the server response as well:

```csharp
builder.Services.AddAuthentication()
    .AddHawk(options =>
    {
        options.EnableServerAuthorization = true;
        options.IncludeResponsePayloadHash = true; // include a response body hash
        options.CredentialProvider = ...;
    });

app.UseAuthentication();
app.UseHawkServerAuthorization(); // register AFTER UseAuthentication
app.UseAuthorization();
```

Clients can then enable `EnableServerAuthorizationValidation` on `HawkSettings`.

## Credential stores

`ICredentialProvider<TCredential>` resolves a credential by id. Implementations:

| Store | Package |
|---|---|
| In-memory dictionary (`MemoryCredentialProvider<T>`) | built in |
| SQL (Dapper) | `Alastack.HmacAuth.Sql` |
| MongoDB | `Alastack.HmacAuth.MongoDB` |
| LiteDB | `Alastack.HmacAuth.LiteDB` |

Or implement `ICredentialProvider<HmacCredential>` / `ICredentialProvider<HawkCredential>` yourself.

## Replay protection

Every request carries a timestamp and a nonce. Authenticated nonces are stored in `IDataCache` (in-memory by default; registers `IDistributedCache` when available — e.g. Redis) until they expire. Relevant options:

| Option | Default | Description |
|---|---|---|
| `MaxReplayRequestAge` | `60` (s) | How long a nonce is remembered / a request stays valid. |
| `TimeSkew` | `300` (s) | Allowed clock skew between client and server. |
| `CredentialCacheTime` | `300` (s) | How long credentials are cached; `0` disables caching. |
| `TimeOffset` | `0` (ms) | Server clock offset **in milliseconds**. |
| `DisableChallenge` | `true` | By default no `WWW-Authenticate` challenge is written on failure. Set to `false` to return one (e.g. `Stale timestamp.`, or a Hawk challenge carrying `ts`/`tsm` for client clock sync) — useful for debugging and client time correction. |

## Running behind reverse proxies

The request host is part of the signature, so the server must know the host the **client** used. `DefaultHostResolver` reads the leftmost `X-Forwarded-Host` entry automatically — no extra middleware is required.

If other application code also depends on `Request.Host`/`Request.Scheme`, register the ASP.NET Core Forwarded Headers Middleware and restrict which proxies are trusted:

```csharp
using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto,
    ForwardLimit = 5,
    KnownProxies =
    {
        IPAddress.Parse("192.168.1.102"),
        IPAddress.Parse("192.168.1.103")
    }
});
// register before app.UseAuthentication();
```

To trust a whole proxy subnet instead, use `KnownIPNetworks` with `System.Net.IPNetwork` (`KnownNetworks` is obsolete since .NET 8):

```csharp
options.KnownIPNetworks.Add(new System.Net.IPNetwork(IPAddress.Parse("192.168.1.0"), 24));
```

Custom host resolution: implement `IHostResolver` and assign it to `HmacOptions.HostResolver` / `HawkOptions.HostResolver`.

## Customization points

| Option | Description |
|---|---|
| `CredentialProvider` | Where credentials are loaded from. |
| `DataCache` | Custom nonce/credential cache (`IDataCache`). |
| `HostResolver` | Custom host resolution (`IHostResolver`). |
| `TimestampCalculator` | Custom timestamp generation/validation. |
| `AuthorizationParameterExtractor` | Custom `Authorization` header parsing. |
| `Events` | `HmacEvents` / `HawkEvents` hooks (`AuthenticationFailed`, `Challenge`, ...). |

## Breaking changes in 2.3.0

- Default `HashAlgorithm` changed from `MD5` to `SHA256` — clients and servers must be upgraded together (including credentials persisted with an explicit algorithm).
- `IHostResolver.Resolve` signature changed to `Resolve(HttpRequest request)`; `ForwardIndex` was removed from both options classes.
- MAC/signature comparisons are now constant-time.

## Samples

See [samples](https://github.com/kyzala/AlastackHmacAuth/tree/main/samples) for full examples, including a YARP reverse-proxy topology (`ApiHostSample` + `ApiProxy` + `RefitSample`).
