using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SernIdp.Api.Configuration;

namespace SernIdp.Api.Services;

public sealed record TokenResponse(string AccessToken, string TokenType, int ExpiresIn, string Scope);

public interface ITokenService
{
    TokenResponse CreateToken(string subject, string clientId, IReadOnlyCollection<string> scopes);
}

public sealed class JwtTokenService : ITokenService
{
    private readonly OidcRuntimeSettings _settings;
    private readonly SigningCredentials _signingCredentials;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();

    public JwtTokenService(OidcRuntimeSettings settings)
    {
        _settings = settings;
        var keyBytes = Encoding.UTF8.GetBytes(settings.SigningKey);
        if (keyBytes.Length < 32)
        {
            throw new InvalidOperationException("SigningKey must be at least 256 bits for HS256 tokens.");
        }

        _signingCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);
    }

    public TokenResponse CreateToken(string subject, string clientId, IReadOnlyCollection<string> scopes)
    {
        var utcNow = DateTime.UtcNow;
        var expires = utcNow.AddSeconds(_settings.AccessTokenLifetimeSeconds);
        var scopeString = scopes.Count > 0 ? string.Join(' ', scopes) : string.Empty;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new("client_id", clientId)
        };

        if (!string.IsNullOrEmpty(scopeString))
        {
            claims.Add(new("scope", scopeString));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _settings.Issuer.AbsoluteUri,
            Audience = clientId,
            Subject = new ClaimsIdentity(claims),
            NotBefore = utcNow,
            Expires = expires,
            SigningCredentials = _signingCredentials
        };

        var token = _tokenHandler.CreateToken(descriptor);
        var serialized = _tokenHandler.WriteToken(token);

        return new TokenResponse(serialized, "Bearer", _settings.AccessTokenLifetimeSeconds, scopeString);
    }
}
