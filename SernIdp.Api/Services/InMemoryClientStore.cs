using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using SernIdp.Api.Configuration;

namespace SernIdp.Api.Services;

public sealed class InMemoryClientStore : IClientStore
{
    private readonly ConcurrentDictionary<string, OidcClientSettings> _clients;

    public InMemoryClientStore(IEnumerable<OidcClientSettings> clients)
    {
        _clients = new ConcurrentDictionary<string, OidcClientSettings>(
            clients.Select(client => new KeyValuePair<string, OidcClientSettings>(client.ClientId, client)));
    }

    public bool TryGetClient(string clientId, [NotNullWhen(true)] out OidcClientSettings? client)
        => _clients.TryGetValue(clientId, out client);
}
