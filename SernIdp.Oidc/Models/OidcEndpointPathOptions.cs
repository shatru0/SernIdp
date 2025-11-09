using System;

namespace SernIdp.Oidc.Models;

/// <summary>
/// Declares the relative paths used to compose the provider metadata endpoint values.
/// </summary>
public sealed record OidcEndpointPathOptions
{
    private const string DefaultPrefix = "/oauth2";

    public string Authorization { get; init; } = $"{DefaultPrefix}/authorize";

    public string Token { get; init; } = $"{DefaultPrefix}/token";

    public string UserInfo { get; init; } = $"{DefaultPrefix}/userinfo";

    public string Jwks { get; init; } = $"{DefaultPrefix}/.well-known/jwks.json";

    public string? Registration { get; init; }

    public string? EndSession { get; init; } = $"{DefaultPrefix}/endsession";

    public string? PushedAuthorization { get; init; } = $"{DefaultPrefix}/par";

    public string? DeviceAuthorization { get; init; } = $"{DefaultPrefix}/device";

    public string? Introspection { get; init; } = $"{DefaultPrefix}/introspect";

    public string? Revocation { get; init; } = $"{DefaultPrefix}/revocation";

    internal OidcEndpointUris ToAbsoluteUris(Uri issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        return new OidcEndpointUris(
            Authorization: Compose(issuer, Authorization),
            Token: Compose(issuer, Token),
            UserInfo: ComposeOptional(issuer, UserInfo),
            Jwks: Compose(issuer, Jwks),
            Registration: ComposeOptional(issuer, Registration),
            EndSession: ComposeOptional(issuer, EndSession),
            PushedAuthorization: ComposeOptional(issuer, PushedAuthorization),
            DeviceAuthorization: ComposeOptional(issuer, DeviceAuthorization),
            Introspection: ComposeOptional(issuer, Introspection),
            Revocation: ComposeOptional(issuer, Revocation));
    }

    private static string Compose(Uri issuer, string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (Uri.TryCreate(path, UriKind.Absolute, out var absolute) &&
            !string.Equals(absolute.Scheme, Uri.UriSchemeFile, StringComparison.OrdinalIgnoreCase))
        {
            return absolute.AbsoluteUri;
        }

        return new Uri(issuer, path).AbsoluteUri;
    }

    private static string? ComposeOptional(Uri issuer, string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        return Compose(issuer, path);
    }
}
