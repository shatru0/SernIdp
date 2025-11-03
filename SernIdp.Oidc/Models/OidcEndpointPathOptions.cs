using System;

namespace SernIdp.Oidc.Models;

/// <summary>
/// Declares the relative paths used to compose the provider metadata endpoint values.
/// </summary>
public sealed record OidcEndpointPathOptions
{
    public string Authorization { get; init; } = "/connect/authorize";

    public string Token { get; init; } = "/connect/token";

    public string UserInfo { get; init; } = "/connect/userinfo";

    public string Jwks { get; init; } = "/.well-known/jwks.json";

    public string? Registration { get; init; }

    public string? EndSession { get; init; } = "/connect/endsession";

    public string? PushedAuthorization { get; init; } = "/connect/par";

    public string? DeviceAuthorization { get; init; } = "/connect/device";

    public string? Introspection { get; init; } = "/connect/introspect";

    public string? Revocation { get; init; } = "/connect/revocation";

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
        return Uri.TryCreate(path, UriKind.Absolute, out var absolute)
            ? absolute.AbsoluteUri
            : new Uri(issuer, path).AbsoluteUri;
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
