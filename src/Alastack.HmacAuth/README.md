# Alastack.HmacAuth

Client-side **Hmac** and **Hawk** authentication for .NET `HttpClient`. Every outgoing request is signed with a shared key, so the API can verify both the caller's identity and the integrity of the request (method, path, query, host and payload).

Use it together with the server-side package [Alastack.HmacAuth.AspNetCore](https://www.nuget.org/packages/Alastack.HmacAuth.AspNetCore), or against any service that implements the same scheme.

- Source code & samples: https://github.com/kyzala/AlastackHmacAuth

## Installation

```powershell
dotnet add package Alastack.HmacAuth
```

## Quick start — Hmac

Plain `HttpClient`:

```csharp
using Alastack.HmacAuth;

var handler = new HmacDelegatingHandler("appId", "appKey");
var httpClient = new HttpClient(handler)
{
    BaseAddress = new Uri("https://api.example.com/")
};

var items = await httpClient.GetFromJsonAsync<TodoItem[]>("api/TodoItems");
```

With `IHttpClientFactory` / Refit:

```csharp
services.AddHttpClient("api", c => c.BaseAddress = new Uri("https://api.example.com/"))
        .AddHttpMessageHandler(_ => new HmacDelegatingHandler("appId", "appKey"));

// Refit
services.AddRefitClient<IApiClient>()
        .ConfigureHttpClient(c => c.BaseAddress = new Uri("https://api.example.com/"))
        .AddHttpMessageHandler(_ => new HmacDelegatingHandler("appId", "appKey"));
```

To drive the handlers from `IOptionsMonitor<T>` instead of literal credentials (configuration hot-reload, named options, settings validation), use the `Alastack.HmacAuth.Options` package, which provides `OptionsHmacDelegatingHandler` / `OptionsHawkDelegatingHandler`.

The handler adds an `Authorization` header to every request:

```http
Authorization: Hmac {appId}:{timestamp}:{nonce}:{signature}:{payloadHash}
```

`signature` is the Base64 HMAC of `appId`, `timestamp`, `nonce`, `method`, `resource` (path + query), `host`, `port` and `payloadHash`, so the server also authenticates the exact URL and body you sent.

## Quick start — Hawk

```csharp
var handler = new HawkDelegatingHandler("authId", "authKey");
var httpClient = new HttpClient(handler)
{
    BaseAddress = new Uri("https://api.example.com/")
};
```

Hawk additionally supports validating the **server** response. Enable it when the server has `EnableServerAuthorization` turned on:

```csharp
var handler = new HawkDelegatingHandler(new HawkSettings
{
    AuthId = "authId",
    AuthKey = "authKey",
    EnableServerAuthorizationValidation = true, // verify the Server-Authorization response header
    EnableServerTimeValidation = true           // verify the tsm of the WWW-Authenticate timestamp response
});
```

## Settings

`HmacDelegatingHandler` accepts a `HmacSettings`, `HawkDelegatingHandler` accepts a `HawkSettings`:

| Property | Default | Description |
|---|---|---|
| `AppId` / `AuthId` | — | Credential identifier sent in the header. |
| `AppKey` / `AuthKey` | — | Shared key used to sign requests. |
| `HmacAlgorithm` | `HMACSHA256` | HMAC algorithm used for the signature. |
| `HashAlgorithm` | `SHA256` *(changed in 2.3.0, was `MD5`)* | Hash algorithm for the payload hash. Must match the server. |
| `IncludePayloadHash` | `true` | Include a hash of the request body in the signature (protects the payload). |
| `TimeOffset` | `0` | Clock offset **in seconds** applied to the timestamp, for skewed client clocks. |
| `EnableServerAuthorizationValidation` | `false` | Hawk only: validate the `Server-Authorization` response header. |
| `EnableServerTimeValidation` | `false` | Hawk only: validate the server timestamp MAC on `Stale timestamp` responses and automatically adjust `TimeOffset`. |

## Notes

- **Clock sync**: the server rejects requests whose timestamp is outside its allowed skew. Keep the client clock synchronized, or set `TimeOffset`.
- **Host matters**: the request host and port are part of the signature. When calling through a reverse proxy, sign with the host the client connects to — the server resolves the original host from `X-Forwarded-Host`.
- **2.3.0 change**: the default `HashAlgorithm` is now `SHA256` (previously `MD5`). If the server still uses MD5, set `HashAlgorithm = "MD5"` explicitly.

## Samples

See [samples/clients](https://github.com/kyzala/AlastackHmacAuth/tree/main/samples/clients) for console, `HttpClientFactory` and Refit examples, including an end-to-end topology with a YARP reverse proxy.
