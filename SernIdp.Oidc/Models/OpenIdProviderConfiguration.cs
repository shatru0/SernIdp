using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace SernIdp.Oidc.Models;

/// <summary>
/// Represents the payload returned from the OpenID Connect discovery endpoint.
/// </summary>
public sealed record OpenIdProviderConfiguration
{
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    [JsonPropertyName("authorization_endpoint")]
    public required string AuthorizationEndpoint { get; init; }

    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; init; }

    [JsonPropertyName("userinfo_endpoint")]
    public string? UserInfoEndpoint { get; init; }

    [JsonPropertyName("jwks_uri")]
    public required string JwksUri { get; init; }

    [JsonPropertyName("registration_endpoint")]
    public string? RegistrationEndpoint { get; init; }

    [JsonPropertyName("end_session_endpoint")]
    public string? EndSessionEndpoint { get; init; }

    [JsonPropertyName("pushed_authorization_request_endpoint")]
    public string? PushedAuthorizationRequestEndpoint { get; init; }

    [JsonPropertyName("device_authorization_endpoint")]
    public string? DeviceAuthorizationEndpoint { get; init; }

    [JsonPropertyName("introspection_endpoint")]
    public string? IntrospectionEndpoint { get; init; }

    [JsonPropertyName("revocation_endpoint")]
    public string? RevocationEndpoint { get; init; }

    [JsonPropertyName("response_types_supported")]
    public IReadOnlyList<string> ResponseTypesSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("grant_types_supported")]
    public IReadOnlyList<string> GrantTypesSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("scopes_supported")]
    public IReadOnlyList<string> ScopesSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("claims_supported")]
    public IReadOnlyList<string> ClaimsSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("subject_types_supported")]
    public IReadOnlyList<string> SubjectTypesSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("code_challenge_methods_supported")]
    public IReadOnlyList<string> CodeChallengeMethodsSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public IReadOnlyList<string> TokenEndpointAuthMethodsSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("request_object_signing_alg_values_supported")]
    public IReadOnlyList<string> RequestObjectSigningAlgValuesSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("acr_values_supported")]
    public IReadOnlyList<string> AcrValuesSupported { get; init; } = Array.Empty<string>();

    [JsonPropertyName("frontchannel_logout_supported")]
    public bool? FrontChannelLogoutSupported { get; init; }

    [JsonPropertyName("frontchannel_logout_session_supported")]
    public bool? FrontChannelLogoutSessionSupported { get; init; }

    [JsonPropertyName("frontchannel_logout_uri")]
    public string? FrontChannelLogoutUri { get; init; }
}
