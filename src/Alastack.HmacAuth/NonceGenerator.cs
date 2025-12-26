namespace Alastack.HmacAuth;

/// <summary>
/// The default implementation of <see cref="INonceGenerator"/>.
/// </summary>
public class NonceGenerator : INonceGenerator
{
    /// <inheritdoc />
    public string Generate(string id)
    {
        return Guid.NewGuid().ToString("n");
    }
}