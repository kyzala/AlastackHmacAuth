using Alastack.HmacAuth;

namespace Alastack.HmacAuth.Tests;

public class HawkCryptoTests
{
    [Theory]
    [InlineData("header", 1662118565, "abc", "GET", "/api/q?a=1&b=2", "a.b.c", 80, null, null, null, null,
        "hawk.1.header\n1662118565\nabc\nGET\n/api/q?a=1&b=2\na.b.c\n80\n\n\n")]
    [InlineData("response", 1662118565, "abc", "GET", "/api/q?a=1&b=2", "a.b.c", 80, "d6CWRMf5HisgSeLQ8uHWhDehAGa9ki71riGsGVw4FGQ=", null, null, null,
        "hawk.1.response\n1662118565\nabc\nGET\n/api/q?a=1&b=2\na.b.c\n80\nd6CWRMf5HisgSeLQ8uHWhDehAGa9ki71riGsGVw4FGQ=\n\n")]
    [InlineData("header", 1662118565, "abc", "GET", "/api/q?a=1&b=2", "a.b.c", 80, null, "ExtData", null, null,
        "hawk.1.header\n1662118565\nabc\nGET\n/api/q?a=1&b=2\na.b.c\n80\n\nExtData\n")]
    [InlineData("header", 1662118565, "abc", "GET", "/api/q?a=1&b=2", "a.b.c", 80, "d6CWRMf5HisgSeLQ8uHWhDehAGa9ki71riGsGVw4FGQ=", "ExtData", null, null,
        "hawk.1.header\n1662118565\nabc\nGET\n/api/q?a=1&b=2\na.b.c\n80\nd6CWRMf5HisgSeLQ8uHWhDehAGa9ki71riGsGVw4FGQ=\nExtData\n")]
    [InlineData("header", 1662118565, "abc", "GET", "/api/q?a=1&b=2", "a.b.c", 80, "d6CWRMf5HisgSeLQ8uHWhDehAGa9ki71riGsGVw4FGQ=", "ExtData", "app", "dlg",
        "hawk.1.header\n1662118565\nabc\nGET\n/api/q?a=1&b=2\na.b.c\n80\nd6CWRMf5HisgSeLQ8uHWhDehAGa9ki71riGsGVw4FGQ=\nExtData\napp\ndlg\n")]
    public void CalculateMac_Crypto_ReturnSameMac(string type, long timestamp, string nonce, string method, string resource, string host, int port, string? hash, string? ext, string? app, string? dlg, string normalizedString)
    {
        var crypto = GetCrypto();
        var expected = crypto.CalculateMac(normalizedString);
        var parameters = CreateMacParameters(timestamp, nonce, method, resource, host, port, hash, ext, app, dlg);
        var actual = crypto.CalculateMac(type, parameters);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void CalculateTsMac_Crypto_ReturnSameMac()
    {
        var crypto = GetCrypto();
        var expected = crypto.CalculateMac("hawk.1.ts\n1662118565\n");
        var actual = crypto.CalculateTsMac(1662118565);
        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(null, null, "hawk.1.payload\n\n\n")]
    [InlineData(null, "", "hawk.1.payload\n\n\n")]
    [InlineData("", null, "hawk.1.payload\n\n\n")]
    [InlineData("", "", "hawk.1.payload\n\n\n")]
    [InlineData("{\"name\": \"tom\"}", "application/json", "hawk.1.payload\napplication/json\n{\"name\": \"tom\"}\n")]
    [InlineData("{\"name\": \"tom\"}", "APPLICATION/JSON", "hawk.1.payload\napplication/json\n{\"name\": \"tom\"}\n")]
    [InlineData("some data", "text/plain", "hawk.1.payload\ntext/plain\nsome data\n")]
    public void CalculatePayloadHash_Crypto_ReturnSameHash(string? payload, string? contentType, string normalizedString)
    {
        var crypto = GetCrypto();
        var expected = crypto.CalculateHash(normalizedString);
        var actual = crypto.CalculatePayloadHash(payload, contentType);
        Assert.Equal(expected, actual);
    }

    private static HawkRawData CreateMacParameters(long timestamp, string nonce, string method, string resource, string host, int port, string? hash, string? ext, string? app, string? dlg)
    {
        return new HawkRawData
        {
            Timestamp = timestamp,
            Nonce = nonce,
            Method = method,
            Resource = resource,
            Host = host,
            Port = port,
            Hash = hash,
            Ext = ext,
            App = app,
            Dlg = dlg
        };
    }

    private static ICrypto GetCrypto()
    {
        return new DefaultCryptoFactory().Create("hmacsha256", "sha256", "3@uo45er?");
    }
}