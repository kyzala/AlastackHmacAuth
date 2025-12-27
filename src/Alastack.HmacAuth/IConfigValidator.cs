using System;
using System.Collections.Generic;
using System.Text;

namespace Alastack.HmacAuth;

/// <summary>
/// Validates config.
/// </summary>
/// <typeparam name="TConfig">The config type to validate.</typeparam>
public interface IConfigValidator<TConfig>
{
    /// <summary>
    /// Validates a specified config instance
    /// </summary>
    /// <param name="config">The config instance.</param>
    /// <returns>ValidateConfigResult</returns>
    ValidateConfigResult Validate(TConfig config);
}


