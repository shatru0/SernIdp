namespace SernIdp.Oidc.Models;

/// <summary>
/// Holds the absolute endpoint values used by the discovery document.
/// </summary>
public sealed record OidcEndpointUris(
    string Authorization,
    string Token,
    string? UserInfo,
    string Jwks,
    string? Registration,
    string? EndSession,
    string? PushedAuthorization,
    string? DeviceAuthorization,
    string? Introspection,
    string? Revocation);
