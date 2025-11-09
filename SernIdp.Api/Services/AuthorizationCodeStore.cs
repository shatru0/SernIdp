using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SernIdp.Api.Services;

public sealed record AuthorizationCodeTicket(
    string ClientId,
    string RedirectUri,
    string? Scope,
    string CodeChallenge,
    string CodeChallengeMethod,
    DateTimeOffset ExpiresAt);

public interface IAuthorizationCodeStore
{
    string CreateCode(string clientId, string redirectUri, string? scope, string codeChallenge, string codeChallengeMethod, TimeSpan lifetime);

    bool TryRedeem(string code, out AuthorizationCodeTicket? ticket);
}

public sealed class AuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly ConcurrentDictionary<string, AuthorizationCodeTicket> _codes = new();

    public string CreateCode(string clientId, string redirectUri, string? scope, string codeChallenge, string codeChallengeMethod, TimeSpan lifetime)
    {
        var code = GenerateCode();
        var ticket = new AuthorizationCodeTicket(
            clientId,
            redirectUri,
            scope,
            codeChallenge,
            codeChallengeMethod,
            DateTimeOffset.UtcNow.Add(lifetime));

        _codes[code] = ticket;
        return code;
    }

    public bool TryRedeem(string code, out AuthorizationCodeTicket? ticket)
    {
        ticket = null;

        if (!_codes.TryRemove(code, out var stored))
        {
            return false;
        }

        if (stored.ExpiresAt < DateTimeOffset.UtcNow)
        {
            return false;
        }

        ticket = stored;
        return true;
    }

    private static string GenerateCode()
    {
        Span<byte> buffer = stackalloc byte[32];
        RandomNumberGenerator.Fill(buffer);
        return Base64UrlEncode(buffer);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> buffer)
        => Convert.ToBase64String(buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
