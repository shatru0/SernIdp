using System.Linq;
using SernIdp.Api.Configuration;
using SernIdp.Api.Services;
using SernIdp.Oidc;
using SernIdp.Oidc.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var oidcSection = builder.Configuration.GetSection("Oidc");
var configuredOptions = oidcSection.Get<OpenIdProviderOptions>();
var runtimeSettings = new OidcRuntimeSettings();
oidcSection.Bind(runtimeSettings);

runtimeSettings = runtimeSettings with
{
    SigningKey = string.IsNullOrWhiteSpace(runtimeSettings.SigningKey)
        ? "change-me-development-signing-key-0123456789"
        : runtimeSettings.SigningKey,
    AccessTokenLifetimeSeconds = runtimeSettings.AccessTokenLifetimeSeconds > 0
        ? runtimeSettings.AccessTokenLifetimeSeconds
        : 3600
};

foreach (var client in runtimeSettings.Clients)
{
    if (client.AllowedGrantTypes.Count == 0)
    {
        client.AllowedGrantTypes.AddRange(new[] { "client_credentials", "authorization_code" });
    }

    if (client.AllowedScopes.Count == 0)
    {
        client.AllowedScopes.AddRange(new[] { "openid", "profile" });
    }
}

var oidcOptions = BuildProviderOptions(configuredOptions, runtimeSettings);

builder.Services.AddSingleton(runtimeSettings);
builder.Services.AddSingleton(oidcOptions);
builder.Services.AddSingleton<IClientStore>(sp =>
{
    var settings = sp.GetRequiredService<OidcRuntimeSettings>();
    return new InMemoryClientStore(settings.Clients);
});
builder.Services.AddSingleton<IAuthorizationCodeStore, AuthorizationCodeStore>();
builder.Services.AddSingleton<ITokenService, JwtTokenService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.WithOpenApi();

app.MapControllers();

app.Run();

static OpenIdProviderOptions BuildProviderOptions(OpenIdProviderOptions? configured, OidcRuntimeSettings runtime)
{
    var options = configured is null
        ? new OpenIdProviderOptions
        {
            Issuer = runtime.Issuer,
            Endpoints = new OidcEndpointPathOptions(),
            GrantTypesSupported = new[] { "authorization_code", "client_credentials" },
            ResponseTypesSupported = new[] { "code" },
            CodeChallengeMethodsSupported = new[] { "S256" }
        }
        : configured with
        {
            Issuer = runtime.Issuer,
            Endpoints = configured.Endpoints ?? new OidcEndpointPathOptions()
        };

    if (options.ResponseTypesSupported.Count == 0)
    {
        options = options with { ResponseTypesSupported = new[] { "code" } };
    }

    if (options.CodeChallengeMethodsSupported.Count == 0)
    {
        options = options with { CodeChallengeMethodsSupported = new[] { "S256" } };
    }

    var authMethods = options.TokenEndpointAuthMethodsSupported.Count > 0
        ? options.TokenEndpointAuthMethodsSupported
            .Concat(new[] { "client_secret_post" })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray()
        : new[] { "client_secret_basic", "client_secret_post" };

    options = options with { TokenEndpointAuthMethodsSupported = authMethods };

    var grantTypes = runtime.Clients
        .SelectMany(client => client.AllowedGrantTypes)
        .Where(type => !string.IsNullOrWhiteSpace(type))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    if (!grantTypes.Contains("authorization_code", StringComparer.OrdinalIgnoreCase))
    {
        grantTypes.Add("authorization_code");
    }

    if (!grantTypes.Contains("client_credentials", StringComparer.OrdinalIgnoreCase))
    {
        grantTypes.Add("client_credentials");
    }

    options = options with { GrantTypesSupported = grantTypes.ToArray() };

    var scopes = runtime.Clients
        .SelectMany(client => client.AllowedScopes)
        .Where(scope => !string.IsNullOrWhiteSpace(scope))
        .Distinct(StringComparer.Ordinal)
        .ToArray();

    if (scopes.Length > 0)
    {
        options = options with { ScopesSupported = scopes };
    }

    return options;
}

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
