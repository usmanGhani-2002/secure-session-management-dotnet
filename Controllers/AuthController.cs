using IdentityLoggerDemo.Data;
using IdentityLoggerDemo.Dto;
using IdentityLoggerDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;

namespace IdentityLoggerDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ApplicationDbContext _db;
        private readonly ILogger<AuthController> _logger;
        private readonly IConfiguration _config;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            ApplicationDbContext db,
            ILogger<AuthController> logger,
            IConfiguration config)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _db = db;
            _logger = logger;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FullName = model.FullName
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Registration failed for {Email}. Errors: {Errors}",
                    model.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                return BadRequest(result.Errors);
            }

            await _userManager.AddToRoleAsync(user, "User");

            _logger.LogInformation("User {Email} registered successfully with role: User", model.Email);
            return Ok(new { Message = "User registered successfully." });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                _logger.LogWarning("Login attempt failed: User {Email} not found.", model.Email);
                return Unauthorized("Invalid credentials.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Login failed for {Email}. Account is locked.", model.Email);
                return Unauthorized("Account is locked. Please try again later.");
            }

            var check = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
            if (!check.Succeeded)
            {
                _logger.LogWarning("Login failed for {Email}. Incorrect password.", model.Email);

                if (check.IsLockedOut)
                {
                    return Unauthorized("Account locked due to multiple failed attempts.");
                }

                return Unauthorized("Invalid credentials.");
            }

            await RevokeOldRefreshTokensForUser(user.Id);

            var accessToken = await GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(Convert.ToDouble(_config["Jwt:RefreshTokenDurationDays"])),
                IsRevoked = false,
                CreatedByIp = GetIpAddress()
            };
            _db.RefreshTokens.Add(refreshTokenEntity);
            await _db.SaveChangesAsync();

            _logger.LogInformation("User {Email} logged in successfully. Tokens issued.", model.Email);

            return Ok(new
            {
                AccessToken = accessToken,
                ExpiresInMinutes = Convert.ToInt32(_config["Jwt:AccessTokenDurationMinutes"]),
                RefreshToken = refreshToken
            });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequestDto model)
        {
            var existingToken = await _db.RefreshTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Token == model.RefreshToken);

            if (existingToken == null || existingToken.IsRevoked || existingToken.ExpiresAt <= DateTime.UtcNow)
            {
                _logger.LogWarning("Refresh failed for token: {Token} from IP: {IP}",
                    model.RefreshToken?.Substring(0, 10) + "...", GetIpAddress());
                return Unauthorized("Invalid or expired refresh token.");
            }

            var user = existingToken.User;
            if (user == null)
            {
                _logger.LogWarning("Refresh failed: user not found for token.");
                return Unauthorized("Invalid refresh token.");
            }

            if (await _userManager.IsLockedOutAsync(user))
            {
                _logger.LogWarning("Refresh denied for locked account: {Email}", user.Email);
                return Unauthorized("Account is locked.");
            }

            var newRefreshToken = GenerateRefreshToken();
            existingToken.IsRevoked = true;
            existingToken.RevokedAt = DateTime.UtcNow;
            existingToken.ReplacedByToken = newRefreshToken;
            existingToken.RevokedByIp = GetIpAddress();

            var newRefreshTokenEntity = new RefreshToken
            {
                Token = newRefreshToken,
                UserId = user.Id,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(Convert.ToDouble(_config["Jwt:RefreshTokenDurationDays"])),
                IsRevoked = false,
                CreatedByIp = GetIpAddress()
            };

            _db.RefreshTokens.Add(newRefreshTokenEntity);
            await _db.SaveChangesAsync();

            var newAccessToken = await GenerateJwtToken(user);
            _logger.LogInformation("Refresh successful for user {Email}. New tokens issued.", user.Email);

            return Ok(new
            {
                AccessToken = newAccessToken,
                ExpiresInMinutes = Convert.ToInt32(_config["Jwt:AccessTokenDurationMinutes"]),
                RefreshToken = newRefreshToken
            });
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutDto model)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            var token = await _db.RefreshTokens.FirstOrDefaultAsync(t => t.Token == model.RefreshToken);
            if (token != null)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedByIp = GetIpAddress();
                await _db.SaveChangesAsync();
                _logger.LogInformation("Refresh token revoked for user id {UserId}", token.UserId);
            }

            await _signInManager.SignOutAsync();

            return Ok(new { Message = "Logged out successfully." });
        }

        [Authorize]
        [HttpPost("logout-all")]
        public async Task<IActionResult> LogoutAll()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized();
            }

            var tokens = await _db.RefreshTokens
                .Where(t => t.UserId == userId && !t.IsRevoked)
                .ToListAsync();

            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedByIp = GetIpAddress();
            }

            await _db.SaveChangesAsync();
            _logger.LogInformation("All refresh tokens revoked for user id {UserId}. Count: {Count}", userId, tokens.Count);

            return Ok(new { Message = $"Logged out from all devices. {tokens.Count} sessions terminated." });
        }

        [Authorize]
        [HttpGet("profile")]
        public async Task<IActionResult> Profile()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound("User not found.");
            }

            var roles = await _userManager.GetRolesAsync(user);

            _logger.LogInformation("Profile accessed by {Email}", user.Email);

            return Ok(new
            {
                Email = user.Email,
                FullName = user.FullName,
                Roles = roles,
                Message = "Profile retrieved successfully."
            });
        }


        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnly()
        {
            return Ok(new { Message = "This endpoint is only accessible by Admins." });
        }

        [Authorize(Roles = "Admin,Moderator")]
        [HttpGet("admin-or-moderator")]
        public IActionResult AdminOrModerator()
        {
            return Ok(new { Message = "This endpoint is accessible by Admins or Moderators." });
        }

        [Authorize]
        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleDto model)
        {
            // Security: Only admins should be able to assign roles
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var isAdmin = await _userManager.IsInRoleAsync(currentUser, "Admin");

            if (!isAdmin)
            {
                _logger.LogWarning("Unauthorized role assignment attempt by {Email}", currentUser?.Email);
                return Forbid();
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            // Ensure role exists
            if (!await _roleManager.RoleExistsAsync(model.RoleName))
            {
                return BadRequest($"Role '{model.RoleName}' does not exist.");
            }

            var result = await _userManager.AddToRoleAsync(user, model.RoleName);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            _logger.LogInformation("Role {Role} assigned to user {Email} by {Admin}",
                model.RoleName, model.Email, currentUser?.Email);

            return Ok(new { Message = $"Role '{model.RoleName}' assigned successfully." });
        }


        [Authorize(Roles = "Admin")]
        [HttpGet("active-sessions")]
        public async Task<IActionResult> GetActiveSessions([FromQuery] string? email = null)
        {
            IQueryable<RefreshToken> query = _db.RefreshTokens
                .Include(t => t.User)
                .Where(t => !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow);

            if (!string.IsNullOrEmpty(email))
            {
                query = query.Where(t => t.User.Email == email);
            }

            var sessions = await query
                .Select(t => new
                {
                    Email = t.User.Email,
                    CreatedAt = t.CreatedAt,
                    ExpiresAt = t.ExpiresAt,
                    CreatedByIp = t.CreatedByIp,
                    TokenPreview = t.Token.Substring(0, 10) + "..."
                })
                .OrderByDescending(t => t.CreatedAt)
                .ToListAsync();

            return Ok(sessions);
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("revoke-user-sessions")]
        public async Task<IActionResult> RevokeUserSessions([FromBody] RevokeUserSessionsDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            var tokens = await _db.RefreshTokens
                .Where(t => t.UserId == user.Id && !t.IsRevoked)
                .ToListAsync();

            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
                token.RevokedByIp = GetIpAddress();
            }

            await _db.SaveChangesAsync();

            _logger.LogInformation("Admin revoked all sessions for user {Email}. Count: {Count}",
                model.Email, tokens.Count);

            return Ok(new { Message = $"Revoked {tokens.Count} active sessions for {model.Email}." });
        }


        private async Task<string> GenerateJwtToken(ApplicationUser user)
        {
            var jwtSettings = _config.GetSection("Jwt");
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email ?? ""),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Security: Unique token ID
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email ?? "")
            };

            if (!string.IsNullOrWhiteSpace(user.FullName))
                claims.Add(new Claim("FullName", user.FullName));

            // Add roles to JWT claims
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["AccessTokenDurationMinutes"])),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

        private string GetIpAddress()
        {
            // Security: Track IP addresses for audit trail
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"].ToString();

            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }

        private async Task RevokeOldRefreshTokensForUser(string userId)
        {

            var oldTokens = await _db.RefreshTokens
                .Where(t => t.UserId == userId && !t.IsRevoked)
                .ToListAsync();

            foreach (var token in oldTokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
            }

        }
    }
}