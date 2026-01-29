using IdentityLoggerDemo.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityLoggerDemo.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configure RefreshToken
            builder.Entity<RefreshToken>(entity =>
            {
                entity.HasKey(e => e.Id);

                entity.HasIndex(e => e.Token)
                      .IsUnique();

                entity.HasIndex(e => e.UserId);

                entity.HasIndex(e => new { e.UserId, e.IsRevoked, e.ExpiresAt });

                entity.HasOne(e => e.User)
                      .WithMany()
                      .HasForeignKey(e => e.UserId)
                      .OnDelete(DeleteBehavior.Cascade);

                entity.Property(e => e.Token)
                      .IsRequired()
                      .HasMaxLength(500);

                entity.Property(e => e.CreatedByIp)
                      .HasMaxLength(50);

                entity.Property(e => e.RevokedByIp)
                      .HasMaxLength(50);

                entity.Property(e => e.ReplacedByToken)
                      .HasMaxLength(500);
            });
        }
    }
}
