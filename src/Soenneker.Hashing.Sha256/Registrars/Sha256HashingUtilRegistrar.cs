using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Hashing.Sha256.Abstract;

namespace Soenneker.Hashing.Sha256.Registrars;

/// <summary>
/// Registration extensions for <see cref="ISha256HashingUtil"/>.
/// </summary>
public static class Sha256HashingUtilRegistrar
{
    /// <summary>
    /// Adds <see cref="ISha256HashingUtil"/> as a singleton service when it has not already been registered.
    /// </summary>
    public static IServiceCollection AddSha256HashingUtilAsSingleton(this IServiceCollection services)
    {
        services.TryAddSingleton<ISha256HashingUtil, Sha256HashingUtil>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="ISha256HashingUtil"/> as a scoped service when it has not already been registered.
    /// </summary>
    public static IServiceCollection AddSha256HashingUtilAsScoped(this IServiceCollection services)
    {
        services.TryAddScoped<ISha256HashingUtil, Sha256HashingUtil>();

        return services;
    }
}
