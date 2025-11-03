using System;
using System.Linq;
using SernIdp.Oidc.Models;

namespace SernIdp.Oidc;

/// <summary>
/// Produces OpenID Connect discovery artifacts.
/// </summary>
public static class OidcWellKnownGenerator
{
    public static OpenIdProviderConfiguration CreateConfiguration(OpenIdProviderOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Issuer is not { IsAbsoluteUri: true })
        {
            throw new ArgumentException("Issuer must be an absolute URI.", nameof(options));
        }

        var endpoints = (options.Endpoints ?? new OidcEndpointPathOptions()).ToAbsoluteUris(options.Issuer);

        return new OpenIdProviderConfiguration
        {
            Issuer = TrimIssuer(options.Issuer),
            AuthorizationEndpoint = endpoints.Authorization,
            TokenEndpoint = endpoints.Token,
            UserInfoEndpoint = endpoints.UserInfo,
            JwksUri = endpoints.Jwks,
            RegistrationEndpoint = endpoints.Registration,
            EndSessionEndpoint = endpoints.EndSession,
            PushedAuthorizationRequestEndpoint = endpoints.PushedAuthorization,
            DeviceAuthorizationEndpoint = endpoints.DeviceAuthorization,
            IntrospectionEndpoint = endpoints.Introspection,
            RevocationEndpoint = endpoints.Revocation,
            ResponseTypesSupported = (options.ResponseTypesSupported ?? Array.Empty<string>()).ToArray(),
            GrantTypesSupported = (options.GrantTypesSupported ?? Array.Empty<string>()).ToArray(),
            ScopesSupported = (options.ScopesSupported ?? Array.Empty<string>()).ToArray(),
            ClaimsSupported = (options.ClaimsSupported ?? Array.Empty<string>()).ToArray(),
            SubjectTypesSupported = (options.SubjectTypesSupported ?? Array.Empty<string>()).ToArray(),
            IdTokenSigningAlgValuesSupported = (options.IdTokenSigningAlgValuesSupported ?? Array.Empty<string>()).ToArray(),
            CodeChallengeMethodsSupported = (options.CodeChallengeMethodsSupported ?? Array.Empty<string>()).ToArray(),
            TokenEndpointAuthMethodsSupported = (options.TokenEndpointAuthMethodsSupported ?? Array.Empty<string>()).ToArray(),
            RequestObjectSigningAlgValuesSupported = (options.RequestObjectSigningAlgValuesSupported ?? Array.Empty<string>()).ToArray(),
            AcrValuesSupported = (options.AcrValuesSupported ?? Array.Empty<string>()).ToArray(),
            FrontChannelLogoutSupported = options.FrontChannelLogoutSupported,
            FrontChannelLogoutSessionSupported = options.FrontChannelLogoutSessionSupported,
            FrontChannelLogoutUri = options.FrontChannelLogoutUri?.AbsoluteUri
        };
    }

    private static string TrimIssuer(Uri issuer)
    {
        var issuerValue = issuer.AbsoluteUri;
        return issuerValue.Length > 1 && issuerValue.EndsWith("/", StringComparison.Ordinal)
            ? issuerValue.TrimEnd('/')
            : issuerValue;
    }
}
