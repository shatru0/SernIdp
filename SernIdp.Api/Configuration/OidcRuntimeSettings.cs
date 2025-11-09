using System;
using System.Collections.Generic;

namespace SernIdp.Api.Configuration;

/// <summary>
/// Collects runtime settings required to serve OAuth 2.0/OIDC requests.
/// </summary>
public sealed record OidcRuntimeSettings
{
    public Uri Issuer { get; init; } = new("https://localhost");

    public string SigningKey { get; init; } = "replace-me-with-a-secure-key";

    public int AccessTokenLifetimeSeconds { get; init; } = 3600;

    public List<OidcClientSettings> Clients { get; init; } = new();
}
