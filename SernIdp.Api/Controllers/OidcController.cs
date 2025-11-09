using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using SernIdp.Api.Configuration;
using SernIdp.Api.Services;
using SernIdp.Oidc;
using SernIdp.Oidc.Models;

namespace SernIdp.Api.Controllers;

/// <summary>
/// Exposes the basic OAuth 2.0 and OpenID Connect endpoints.
/// Supports client credentials and authorization-code (PKCE) flows.
/// </summary>
[ApiController]
[Route("oauth2")]
public sealed class OidcController : ControllerBase
{
    private const string AuthorizationCodeGrant = "authorization_code";
    private const string ClientCredentialsGrant = "client_credentials";
    private static readonly TimeSpan AuthorizationCodeLifetime = TimeSpan.FromMinutes(5);
    private static readonly object EmptyJwks = new { keys = Array.Empty<object>() };

    private readonly OpenIdProviderOptions _providerOptions;
    private readonly IClientStore _clientStore;
    private readonly IAuthorizationCodeStore _authorizationCodes;
    private readonly ITokenService _tokenService;

    public OidcController(
        OpenIdProviderOptions providerOptions,
        IClientStore clientStore,
        IAuthorizationCodeStore authorizationCodes,
        ITokenService tokenService)
    {
        _providerOptions = providerOptions;
        _clientStore = clientStore;
        _authorizationCodes = authorizationCodes;
        _tokenService = tokenService;
    }

    [HttpGet(".well-known/openid-configuration")]
    [ProducesResponseType(typeof(OpenIdProviderConfiguration), StatusCodes.Status200OK)]
    public ActionResult<OpenIdProviderConfiguration> GetConfiguration()
        => Ok(OidcWellKnownGenerator.CreateConfiguration(_providerOptions));

    [HttpGet("authorize")]
    public IActionResult Authorize([FromQuery] AuthorizationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            return OAuthError("invalid_request", "client_id is required.");
        }

        if (!_clientStore.TryGetClient(request.ClientId, out var client))
        {
            return OAuthError("invalid_client", "Unknown client_id.");
        }

        if (!string.Equals(request.ResponseType, "code", StringComparison.Ordinal))
        {
            return OAuthError("unsupported_response_type", "Only the authorization code response_type is supported.");
        }

        if (!client.AllowedGrantTypes.Contains(AuthorizationCodeGrant, StringComparer.OrdinalIgnoreCase))
        {
            return OAuthError("unauthorized_client", "Client is not allowed to use the authorization_code grant.");
        }

        if (string.IsNullOrWhiteSpace(request.RedirectUri))
        {
            return OAuthError("invalid_request", "redirect_uri is required.");
        }

        if (!client.RedirectUris.Contains(request.RedirectUri, StringComparer.Ordinal))
        {
            return OAuthError("invalid_request", "redirect_uri is not registered for this client.");
        }

        if (string.IsNullOrWhiteSpace(request.CodeChallenge))
        {
            return OAuthError("invalid_request", "code_challenge is required for PKCE.");
        }

        var method = request.CodeChallengeMethod ?? "S256";
        if (!string.Equals(method, "S256", StringComparison.OrdinalIgnoreCase))
        {
            return OAuthError("invalid_request", "Only S256 code_challenge_method is supported.");
        }

        if (!TryResolveScopes(request.Scope, client, out var scopes, out var scopeError))
        {
            return scopeError!;
        }

        var scopeString = scopes.Count > 0 ? string.Join(' ', scopes) : null;
        var code = _authorizationCodes.CreateCode(
            client.ClientId,
            request.RedirectUri,
            scopeString,
            request.CodeChallenge,
            method,
            AuthorizationCodeLifetime);

        var parameters = new Dictionary<string, string?>
        {
            ["code"] = code,
            ["state"] = request.State
        };

        var redirectUri = QueryHelpers.AddQueryString(request.RedirectUri, parameters!);
        return Redirect(redirectUri);
    }

    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public IActionResult Token([FromForm] TokenRequest request)
    {
        if (!TryGetClientCredentials(request, out var clientId, out var clientSecret, out var credentialError))
        {
            return credentialError ?? OAuthError("invalid_client", "Client authentication failed.");
        }

        if (!_clientStore.TryGetClient(clientId!, out var client))
        {
            return OAuthError("invalid_client", "Client authentication failed.", StatusCodes.Status401Unauthorized);
        }

        var grantType = request.GrantType;
        if (string.IsNullOrWhiteSpace(grantType))
        {
            return OAuthError("invalid_request", "grant_type is required.");
        }

        if (!client.AllowedGrantTypes.Contains(grantType, StringComparer.OrdinalIgnoreCase))
        {
            return OAuthError("unauthorized_client", "The specified grant_type is not allowed for this client.");
        }

        if (!ValidateClientSecret(client, clientSecret, grantType))
        {
            return OAuthError("invalid_client", "Client authentication failed.", StatusCodes.Status401Unauthorized);
        }

        return grantType switch
        {
            ClientCredentialsGrant => HandleClientCredentials(client, request.Scope),
            AuthorizationCodeGrant => HandleAuthorizationCode(client, request),
            _ => OAuthError("unsupported_grant_type", $"Unsupported grant_type '{grantType}'.")
        };
    }

    [HttpGet("userinfo")]
    public IActionResult UserInfo()
        => NotImplemented();

    [HttpGet(".well-known/jwks.json")]
    public IActionResult Jwks()
        => Ok(EmptyJwks);

    [HttpPost("par")]
    public IActionResult PushedAuthorizationRequest()
        => NotImplemented();

    [HttpPost("device")]
    public IActionResult DeviceAuthorization()
        => NotImplemented();

    [HttpPost("introspect")]
    public IActionResult Introspect()
        => NotImplemented();

    [HttpPost("revocation")]
    public IActionResult Revoke()
        => NotImplemented();

    [HttpGet("endsession")]
    public IActionResult EndSession()
        => NotImplemented();

    private IActionResult HandleClientCredentials(OidcClientSettings client, string? scopeParameter)
    {
        if (!TryResolveScopes(scopeParameter, client, out var scopes, out var scopeError))
        {
            return scopeError!;
        }

        var token = _tokenService.CreateToken(client.ClientId, client.ClientId, scopes);
        return Ok(new
        {
            access_token = token.AccessToken,
            token_type = token.TokenType,
            expires_in = token.ExpiresIn,
            scope = token.Scope
        });
    }

    private IActionResult HandleAuthorizationCode(OidcClientSettings client, TokenRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Code))
        {
            return OAuthError("invalid_request", "code is required for the authorization_code grant.");
        }

        if (string.IsNullOrWhiteSpace(request.RedirectUri))
        {
            return OAuthError("invalid_request", "redirect_uri must match the authorization request.");
        }

        if (string.IsNullOrWhiteSpace(request.CodeVerifier))
        {
            return OAuthError("invalid_request", "code_verifier is required when exchanging an authorization code.");
        }

        if (!_authorizationCodes.TryRedeem(request.Code, out var ticket) || ticket is null)
        {
            return OAuthError("invalid_grant", "The authorization code is invalid or has expired.");
        }

        if (!string.Equals(ticket.ClientId, client.ClientId, StringComparison.Ordinal))
        {
            return OAuthError("invalid_grant", "Authorization code was not issued to this client.");
        }

        if (!string.Equals(ticket.RedirectUri, request.RedirectUri, StringComparison.Ordinal))
        {
            return OAuthError("invalid_grant", "redirect_uri does not match the original authorization request.");
        }

        if (!ValidateCodeVerifier(request.CodeVerifier, ticket.CodeChallenge, ticket.CodeChallengeMethod))
        {
            return OAuthError("invalid_grant", "PKCE verification failed.");
        }

        var scopes = SplitScopes(ticket.Scope);
        var token = _tokenService.CreateToken(client.ClientId, client.ClientId, scopes);
        return Ok(new
        {
            access_token = token.AccessToken,
            token_type = token.TokenType,
            expires_in = token.ExpiresIn,
            scope = token.Scope
        });
    }

    private static bool TryResolveScopes(string? scopeParameter, OidcClientSettings client, out IReadOnlyCollection<string> scopes, out IActionResult? errorResult)
    {
        var requested = SplitScopes(scopeParameter);

        if (requested.Count == 0)
        {
            scopes = requested;
            errorResult = null;
            return true;
        }

        if (client.AllowedScopes.Count == 0)
        {
            scopes = requested;
            errorResult = null;
            return true;
        }

        var allowed = new HashSet<string>(client.AllowedScopes, StringComparer.Ordinal);
        foreach (var scope in requested)
        {
            if (!allowed.Contains(scope))
            {
                scopes = Array.Empty<string>();
                errorResult = new BadRequestObjectResult(new { error = "invalid_scope", error_description = $"Scope '{scope}' is not permitted for this client." });
                return false;
            }
        }

        scopes = requested;
        errorResult = null;
        return true;
    }

    private static IReadOnlyCollection<string> SplitScopes(string? scopeParameter)
        => string.IsNullOrWhiteSpace(scopeParameter)
            ? Array.Empty<string>()
            : scopeParameter.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private bool TryGetClientCredentials(TokenRequest request, out string? clientId, out string? clientSecret, out IActionResult? errorResult)
    {
        clientId = null;
        clientSecret = null;
        errorResult = null!;

        if (TryReadBasicAuthorizationHeader(out var basicId, out var basicSecret))
        {
            clientId = basicId;
            clientSecret = basicSecret;
        }
        else
        {
            clientId = request.ClientId;
            clientSecret = request.ClientSecret;
        }

        if (string.IsNullOrWhiteSpace(clientId))
        {
            errorResult = OAuthError("invalid_request", "Client authentication is required.");
            return false;
        }

        return true;
    }

    private static bool ValidateClientSecret(OidcClientSettings client, string? providedSecret, string grantType)
    {
        var requiresSecret = string.Equals(grantType, ClientCredentialsGrant, StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(client.ClientSecret);

        if (!requiresSecret)
        {
            return true;
        }

        return !string.IsNullOrEmpty(client.ClientSecret) &&
               string.Equals(client.ClientSecret, providedSecret, StringComparison.Ordinal);
    }

    private bool TryReadBasicAuthorizationHeader(out string? clientId, out string? clientSecret)
    {
        clientId = null;
        clientSecret = null;

        if (!Request.Headers.TryGetValue("Authorization", out var values))
        {
            return false;
        }

        var header = values.FirstOrDefault();
        if (string.IsNullOrEmpty(header))
        {
            return false;
        }

        header = header.Trim();
        const string prefix = "Basic ";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var encoded = header[prefix.Length..].Trim();
        if (string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        try
        {
            var decodedBytes = Convert.FromBase64String(encoded);
            var decoded = Encoding.UTF8.GetString(decodedBytes);
            var separatorIndex = decoded.IndexOf(':');
            if (separatorIndex < 0)
            {
                clientId = decoded;
                clientSecret = string.Empty;
            }
            else
            {
                clientId = decoded[..separatorIndex];
                clientSecret = decoded[(separatorIndex + 1)..];
            }

            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool ValidateCodeVerifier(string codeVerifier, string codeChallenge, string method)
    {
        if (!string.Equals(method, "S256", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        using var sha = SHA256.Create();
        var hashed = sha.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
        var encoded = Convert.ToBase64String(hashed).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return string.Equals(encoded, codeChallenge, StringComparison.Ordinal);
    }

    private static IActionResult OAuthError(string error, string description, int statusCode = StatusCodes.Status400BadRequest)
    {
        var payload = new { error, error_description = description };
        return new ObjectResult(payload) { StatusCode = statusCode };
    }

    private static ObjectResult NotImplemented()
    {
        var payload = new
        {
            error = "not_implemented",
            error_description = "Endpoint wiring is in place, but no behavior has been provided yet."
        };

        return new ObjectResult(payload) { StatusCode = StatusCodes.Status501NotImplemented };
    }

    public sealed class AuthorizationRequest
    {
        [FromQuery(Name = "response_type")]
        public string? ResponseType { get; init; }

        [FromQuery(Name = "client_id")]
        public string? ClientId { get; init; }

        [FromQuery(Name = "redirect_uri")]
        public string? RedirectUri { get; init; }

        [FromQuery(Name = "scope")]
        public string? Scope { get; init; }

        [FromQuery(Name = "state")]
        public string? State { get; init; }

        [FromQuery(Name = "code_challenge")]
        public string? CodeChallenge { get; init; }

        [FromQuery(Name = "code_challenge_method")]
        public string? CodeChallengeMethod { get; init; }
    }

    public sealed class TokenRequest
    {
        [FromForm(Name = "grant_type")]
        public string? GrantType { get; init; }

        [FromForm(Name = "client_id")]
        public string? ClientId { get; init; }

        [FromForm(Name = "client_secret")]
        public string? ClientSecret { get; init; }

        [FromForm(Name = "scope")]
        public string? Scope { get; init; }

        [FromForm(Name = "code")]
        public string? Code { get; init; }

        [FromForm(Name = "redirect_uri")]
        public string? RedirectUri { get; init; }

        [FromForm(Name = "code_verifier")]
        public string? CodeVerifier { get; init; }
    }
}
