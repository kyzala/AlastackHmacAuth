using Alastack.HmacAuth;

namespace Alastack.HmacAuth.Tests;

public class CryptoFactoryTests
{
    [Theory]
    [InlineData(null, null, null)]
    [InlineData("HMACSHA1", null, null)]
    [InlineData("HMACSHA1", "SHA1", null)]
    public void Create_CryptoFactory_ThrowArgumentNullExceptionAlgorithmNames(string hmacAlgorithmName, string hashAlgorithmName, string key)
    {
        var factory = new DefaultCryptoFactory();
        Assert.Throws<ArgumentNullException>(() => factory.Create(hmacAlgorithmName, hashAlgorithmName, key));
    }

    //[Theory]
    //[InlineData(null, null)]
    //[InlineData("SHA1", null)]
    //public void Create_CryptoFactory_ThrowArgumentNullExceptionAlgorithmName(string algorithmName, string key)
    //{
    //    var factory = new DefaultCryptoFactory();
    //    Assert.Throws<ArgumentNullException>(() => factory.Create(algorithmName, key));
    //}

    [Theory]
    [InlineData("EDF", "SHA1", "abc1234567890")]
    [InlineData("SHA1", "SHA1", "abc1234567890")]
    public void Create_CryptoFactory_ThrowArgumentExceptionAlgorithmNames(string hmacAlgorithmName, string hashAlgorithmName, string key)
    {
        var factory = new DefaultCryptoFactory();
        Assert.Throws<ArgumentException>(() => factory.Create(hmacAlgorithmName, hashAlgorithmName, key));
    }

    [Theory]
    [InlineData("HMACMD5", "MD5", "abc1234567890")]
    [InlineData("hmacsha1", "sha1", "abc1234567890")]
    [InlineData("HMACSHA256", "sha256", "abc1234567890")]
    [InlineData("HmacMD5", "SHA384", "abc1234567890")]
    [InlineData("HMACSHA512", "sha1", "abc1234567890")]
    public void Create_CryptoFactory_ValidateAlgorithmNamesSuccess(string hmacAlgorithmName, string hashAlgorithmName, string key)
    {
        var factory = new DefaultCryptoFactory();
        var crypto = factory.Create(hmacAlgorithmName, hashAlgorithmName, key);
        Assert.NotNull(crypto);
    }

    //[Theory]
    //[InlineData("sha", "abc1234567890")]
    //[InlineData("hmacsha1", "abc1234567890")]
    //public void Create_CryptoFactory_ThrowArgumentExceptionAlgorithmName(string algorithmName, string key)
    //{
    //    var factory = new DefaultCryptoFactory();
    //    Assert.Throws<ArgumentException>(() => factory.Create(algorithmName, key));
    //}

    //[Theory]
    //[InlineData("sha1", "abc1234567890")]
    //[InlineData("Sha256", "abc1234567890")]
    //[InlineData("SHA256", "abc1234567890")]
    //[InlineData("md5", "abc1234567890")]
    //public void Create_CryptoFactory_ValidateAlgorithmNameSuccess(string algorithmName, string key)
    //{
    //    var factory = new DefaultCryptoFactory();
    //    var crypto = factory.Create(algorithmName, key);
    //    Assert.NotNull(crypto);
    //}
}