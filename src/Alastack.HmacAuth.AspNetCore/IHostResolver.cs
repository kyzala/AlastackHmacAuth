using Microsoft.AspNetCore.Http;

namespace Alastack.HmacAuth.AspNetCore;

/// <summary>
/// A host resolver abstraction.
/// </summary>
public interface IHostResolver
{
    /// <summary>
    /// Resolve host information from the HTTP request.
    /// </summary>
    /// <param name="request">Represents the incoming side of an individual HTTP request.</param>
    /// <returns>Represents the host portion of a URI.</returns>
    HostString Resolve(HttpRequest request);
}