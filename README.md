# Alastack HmacAuth

Hmac and [Hawk](https://github.com/mozilla/hawk) authentication for .NET. Every client request is signed with a shared key, so the server can verify the caller's identity and the integrity of the request, and reject replayed traffic using a timestamp and nonce.

[![Build & Tests](https://img.shields.io/github/actions/workflow/status/kyzala/AlastackHmacAuth/dotnet.yml?branch=main&label=build%20%26%20tests)](https://github.com/kyzala/AlastackHmacAuth/actions/workflows/dotnet.yml)
[![NuGet](https://img.shields.io/nuget/v/Alastack.HmacAuth)](https://www.nuget.org/packages/Alastack.HmacAuth)
[![License](https://img.shields.io/github/license/kyzala/AlastackHmacAuth)](LICENSE)

## Features

- **Two schemes, one model** — Hmac for a compact custom header, Hawk for the [Mozilla Hawk](https://github.com/mozilla/hawk) specification, both driven by the same credential and signing pipeline.
- **Full request integrity** — the signature covers the HTTP method, path, query string, host, port and payload hash, so a captured request cannot be replayed against another endpoint or with a modified body.
- **Replay protection** — timestamps are validated against an allowed clock skew and authenticated nonces are cached for a configurable window.
- **Optional Hawk response signing** — clients can verify `Server-Authorization` and correct their clock from a `Stale timestamp` challenge.
- **Pluggable credentials** — in-memory dictionaries plus SQL, MongoDB, LiteDB and Entity Framework Core providers, or your own `ICredentialProvider<T>`.
- **Proxy-aware** — the original client host is recovered from `X-Forwarded-Host`, with validation of forwarded ports and IPv6 addresses.
- **Hardened defaults** — SHA256 payload hashing and constant-time MAC comparison.

## Packages

- **[Alastack.HmacAuth](https://www.nuget.org/packages/Alastack.HmacAuth)** — client handlers for `HttpClient`.
- **[Alastack.HmacAuth.AspNetCore](https://www.nuget.org/packages/Alastack.HmacAuth.AspNetCore)** — server authentication for ASP.NET Core.
- **[Alastack.HmacAuth.Sql](https://www.nuget.org/packages/Alastack.HmacAuth.Sql)** / **[MongoDB](https://www.nuget.org/packages/Alastack.HmacAuth.MongoDB)** / **[LiteDB](https://www.nuget.org/packages/Alastack.HmacAuth.LiteDB)** / **[EFCore](https://www.nuget.org/packages/Alastack.HmacAuth.EFCore)** — credential providers.

Full package documentation: [src/README.md](src/README.md).

## Quick start

```powershell
dotnet add package Alastack.HmacAuth
dotnet add package Alastack.HmacAuth.AspNetCore
```

### Hmac

**Client**

```csharp
var client = new HttpClient(new HmacDelegatingHandler("appId", "appKey"))
{
    BaseAddress = new Uri("https://localhost:5001/")
};
```

**Server**

```csharp
builder.Services.AddAuthentication()
    .AddHmac(options =>
    {
        options.CredentialProvider = new MemoryCredentialProvider<HmacCredential>(
            new Dictionary<string, HmacCredential>
            {
                ["appId"] = new HmacCredential { AppId = "appId", AppKey = "appKey" }
            });
    });

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
```

Endpoints opt in with `[Authorize(AuthenticationSchemes = "Hmac")]`.

### Hawk

**Client**

```csharp
var client = new HttpClient(new HawkDelegatingHandler("authId", "authKey"))
{
    BaseAddress = new Uri("https://localhost:5001/")
};
```

**Server**

```csharp
builder.Services.AddAuthentication()
    .AddHawk(options =>
    {
        options.CredentialProvider = new MemoryCredentialProvider<HawkCredential>(
            new Dictionary<string, HawkCredential>
            {
                ["authId"] = new HawkCredential { AuthId = "authId", AuthKey = "authKey" }
            });
    });

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
```

Endpoints opt in with `[Authorize(AuthenticationSchemes = "Hawk")]`. To sign responses as well, set `EnableServerAuthorization = true` in `AddHawk` and register `app.UseHawkServerAuthorization()` right after `UseAuthentication()`.

## How it works

The Hmac header carries the credential id, timestamp, nonce, signature and payload hash:

```http
Authorization: Hmac {appId}:{timestamp}:{nonce}:{signature}:{payloadHash}
```

On each request the server:

1. resolves the credential by `appId` (or Hawk `id`) through `ICredentialProvider<T>`;
2. rebuilds the canonical string from method, resource, host, port and payload hash, then compares the MAC in constant time;
3. rejects timestamps outside `TimeSkew` and nonces already seen within `MaxReplayRequestAge`;
4. optionally signs the response so the caller can verify the server as well.

Hawk additionally supports `ext`, `mac`, `tsm` and a `Stale timestamp` challenge for clock correction.

## Behind a reverse proxy

Host and port are part of the signature, so the server must see the host the client signed. `DefaultHostResolver` reads the leftmost `X-Forwarded-Host` entry automatically — no extra middleware is required. If other application code depends on `Request.Host`/`Request.Scheme`, register `UseForwardedHeaders` and restrict trust with `KnownProxies` or `KnownIPNetworks`; never accept forwarded headers from arbitrary clients while the app is directly reachable.

## Samples

Runnable examples in [samples](https://github.com/kyzala/AlastackHmacAuth/tree/main/samples):

- `ApiHostSample` — ASP.NET Core host for both schemes, with a `/debug-forwarded` endpoint for inspecting forwarding headers.
- `ApiProxy` — YARP proxy used to verify host resolution behind reverse proxies.
- `ClientBasicSample`, `ClientHostSample` — plain `HttpClient` and `IHttpClientFactory` clients with interactive menus.
- `SqlCredentialSample`, `MongoDBCredentialSample`, `LiteDBCredentialSample`, `EFCoreCredentialSample` — one host per credential store.

Start `ApiHostSample` first, then run a client sample and pick a scheme and operation from the menu.

## Getting help

Use [GitHub Issues](https://github.com/kyzala/AlastackHmacAuth/issues) for bug reports and questions. The unit tests in `test/` are the reference for current behavior.
