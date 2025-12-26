using Microsoft.AspNetCore.Http;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// A host resolver abstraction.
/// </summary>
public interface IHostResolver
{
    /// <summary>
    /// Resolve host information from http headers.
    /// </summary>
    /// <param name="request">Represents the incoming side of an individual HTTP request.</param>
    /// <param name="forwardIndex">Reverse host index of forwarding header. Using 0 base index.</param>
    /// <returns>Represents the host portion of a URI.</returns>
    HostString Resolve(HttpRequest request, int forwardIndex);
}