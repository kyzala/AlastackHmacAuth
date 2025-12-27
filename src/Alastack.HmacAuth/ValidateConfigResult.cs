using System;
using System.Collections.Generic;
using System.Text;

namespace Alastack.HmacAuth;

/// <summary>
/// Represents the result of an config validation.
/// </summary>
public class ValidateConfigResult
{
    /// <summary>
    /// Gets a value that indicates whether validation was successful.
    /// </summary>
    public bool Succeeded { get; protected set; }

    /// <summary>
    /// Gets the description of why validation failed.
    /// </summary>
    public string? FailureMessage { get; protected set; }

    /// <summary>
    /// The result when validation was successful.
    /// </summary>
    public static readonly ValidateConfigResult Success = new()
    {
        Succeeded = true
    };

    /// <summary>
    /// Returns a failure result.
    /// </summary>
    /// <param name="failureMessage">The reason for the failure.</param>
    /// <returns>The failure result.</returns>
    public static ValidateConfigResult Fail(string failureMessage)
    {
        return new ValidateConfigResult
        {
            Succeeded = false,
            FailureMessage = failureMessage
        };
    }
}