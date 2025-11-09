using System.Diagnostics.CodeAnalysis;
using SernIdp.Api.Configuration;

namespace SernIdp.Api.Services;

public interface IClientStore
{
    bool TryGetClient(string clientId, [NotNullWhen(true)] out OidcClientSettings? client);
}
