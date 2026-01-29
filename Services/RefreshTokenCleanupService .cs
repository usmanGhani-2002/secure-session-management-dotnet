using IdentityLoggerDemo.Data;
using Microsoft.EntityFrameworkCore;

namespace IdentityLoggerDemo.Services
{
    /// <summary>
    /// Background service that periodically cleans up expired and revoked refresh tokens
    /// </summary>
    public class RefreshTokenCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<RefreshTokenCleanupService> _logger;
        private readonly TimeSpan _cleanupInterval;
        private readonly int _tokenRetentionDays;

        public RefreshTokenCleanupService(
            IServiceProvider serviceProvider,
            ILogger<RefreshTokenCleanupService> logger,
            IConfiguration configuration)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;

            // Default: run cleanup every 24 hours
            _cleanupInterval = TimeSpan.FromHours(
                configuration.GetValue<int>("RefreshTokenCleanup:IntervalHours", 24));

            // Default: keep revoked/expired tokens for 30 days for audit trail
            _tokenRetentionDays = configuration.GetValue<int>("RefreshTokenCleanup:RetentionDays", 30);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Refresh Token Cleanup Service started. Running every {Hours} hours.",
                _cleanupInterval.TotalHours);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await CleanupExpiredTokens(stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred during token cleanup.");
                }

                // Wait for next cleanup interval
                await Task.Delay(_cleanupInterval, stoppingToken);
            }
        }

        private async Task CleanupExpiredTokens(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var cutoffDate = DateTime.UtcNow.AddDays(-_tokenRetentionDays);

            // Delete tokens that are:
            // 1. Expired or revoked
            // 2. Older than retention period
            var tokensToDelete = await db.RefreshTokens
                .Where(t => (t.IsRevoked || t.ExpiresAt < DateTime.UtcNow)
                         && t.CreatedAt < cutoffDate)
                .ToListAsync(cancellationToken);

            if (tokensToDelete.Any())
            {
                db.RefreshTokens.RemoveRange(tokensToDelete);
                await db.SaveChangesAsync(cancellationToken);

                _logger.LogInformation(
                    "Cleaned up {Count} expired/revoked refresh tokens older than {Days} days.",
                    tokensToDelete.Count, _tokenRetentionDays);
            }
            else
            {
                _logger.LogDebug("No tokens to clean up.");
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Refresh Token Cleanup Service is stopping.");
            return base.StopAsync(cancellationToken);
        }
    }
}