using System;
using System.Collections.Generic;

namespace SernIdp.Oidc.Models;

/// <summary>
/// Describes the data necessary to build the OpenID Connect discovery document.
/// </summary>
public sealed record OpenIdProviderOptions
{
    public required Uri Issuer { get; init; }

    public OidcEndpointPathOptions Endpoints { get; init; } = new();

    public IReadOnlyCollection<string> ResponseTypesSupported { get; init; } = new[] { "code" };

    public IReadOnlyCollection<string> GrantTypesSupported { get; init; } = new[] { "authorization_code" };

    public IReadOnlyCollection<string> ScopesSupported { get; init; } = new[] { "openid", "profile", "email" };

    public IReadOnlyCollection<string> ClaimsSupported { get; init; } = new[] { "sub", "name", "email" };

    public IReadOnlyCollection<string> SubjectTypesSupported { get; init; } = new[] { "public" };

    public IReadOnlyCollection<string> IdTokenSigningAlgValuesSupported { get; init; } = new[] { "RS256" };

    public IReadOnlyCollection<string> CodeChallengeMethodsSupported { get; init; } = new[] { "S256" };

    public IReadOnlyCollection<string> TokenEndpointAuthMethodsSupported { get; init; } = new[] { "client_secret_basic" };

    public IReadOnlyCollection<string> RequestObjectSigningAlgValuesSupported { get; init; } = new[] { "RS256" };

    public IReadOnlyCollection<string> AcrValuesSupported { get; init; } = Array.Empty<string>();

    public bool FrontChannelLogoutSupported { get; init; } = true;

    public bool FrontChannelLogoutSessionSupported { get; init; } = true;

    public Uri? FrontChannelLogoutUri { get; init; }
}
