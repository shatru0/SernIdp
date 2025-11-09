using System;
using System.Collections.Generic;

namespace SernIdp.Api.Configuration;

/// <summary>
/// Represents a client application allowed to interact with the authorization server.
/// </summary>
public sealed record OidcClientSettings
{
    public required string ClientId { get; init; }

    public string? ClientSecret { get; init; }

    public List<string> AllowedGrantTypes { get; init; } = new();

    public List<string> RedirectUris { get; init; } = new();

    public List<string> AllowedScopes { get; init; } = new();
}
