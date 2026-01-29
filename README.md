# Secure JWT Authentication with Refresh Token Rotation

A production-ready ASP.NET Core authentication system implementing JWT access tokens, refresh token rotation, role-based authorization, and comprehensive identity event logging.

---

## Features

- **ASP.NET Core Identity** - User management and password hashing
- **JWT Authentication** - Stateless access tokens
- **Refresh Token Rotation** - Database-tracked token lifecycle
- **Session Revocation** - Server-side logout capability
- **Role-Based Authorization** - Fine-grained access control
- **Identity Event Logging** - Audit trail for security events
- **Background Token Cleanup** - Automatic expired token removal
- **Secure Token Generation** - Cryptographically strong tokens

---

## Authentication Architecture

This system uses a **hybrid authentication model** combining the scalability of JWTs with server-side session control:

- **Short-lived JWT access tokens** (15 minutes) - Stateless authentication
- **Long-lived refresh tokens** (7 days) - Stored in database
- **Token rotation** - Prevents replay attacks
- **Revocation support** - Immediate session termination

---

## Authentication Flow

### 1. Registration & Login
```
User → Credentials → Server
Server validates with ASP.NET Core Identity
Server issues:
  - JWT Access Token (short-lived)
  - Refresh Token (stored in database)
```

### 2. Authenticated Requests
```
Client → Request + Access Token in Authorization header
Server validates JWT
Server processes request
```

### 3. Token Refresh
```
Client → Refresh token
Server validates and revokes old token
Server issues:
  - New Access Token
  - New Refresh Token
```

### 4. Logout
```
Client → Logout request
Server revokes refresh token
Session terminated immediately
```

---

## Project Structure
```
IdentityLoggerDemo/
│
├── Controllers/
│   └── AuthController.cs              # Authentication endpoints
│
├── Data/
│   └── ApplicationDbContext.cs        # EF Core DbContext
│
├── Dto/
│   ├── LoginDto.cs
│   ├── RegisterDto.cs
│   ├── LogoutDto.cs
│   ├── RefreshRequestDto.cs
│   ├── AssignRoleDto.cs
│   └── RevokeUserSessionsDto.cs
│
├── Models/
│   ├── ApplicationUser.cs             # Extended IdentityUser
│   └── RefreshToken.cs                # Token tracking model
│
├── Services/
│   └── RefreshTokenCleanupService.cs  # Background cleanup service
│
├── Migrations/
├── Program.cs
├── appsettings.json
└── README.md
```

---

## API Endpoints

| Method | Endpoint                      | Description                    | Auth Required |
|--------|-------------------------------|--------------------------------|---------------|
| POST   | `/api/auth/register`          | Register new user              | No            |
| POST   | `/api/auth/login`             | Login user                     | No            |
| POST   | `/api/auth/refresh`           | Refresh access token           | No            |
| POST   | `/api/auth/logout`            | Logout current session         | Yes           |
| POST   | `/api/auth/assign-role`       | Assign role to user            | Yes (Admin)   |
| POST   | `/api/auth/revoke-sessions`   | Revoke all user sessions       | Yes (Admin)   |
| GET    | `/api/secure`                 | Protected endpoint example     | Yes           |

---

## Setup Instructions

### 1. Clone Repository
```bash
git clone https://github.com/your-username/IdentityLoggerDemo.git
cd IdentityLoggerDemo
```

### 2. Configure Application Settings

Update `appsettings.json` with your configuration:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=IdentityLoggerDb;Trusted_Connection=True;MultipleActiveResultSets=true"
  },
  "Jwt": {
    "Key": "YourSuperSecretKeyHere-MustBeAtLeast32Characters!",
    "Issuer": "YourIssuer",
    "Audience": "YourAudience",
    "ExpireMinutes": 15
  }
}
```

### 3. Apply Database Migrations
```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

### 4. Run Application
```bash
dotnet run
```

The API will be available at `https://localhost:5001` (or check console output).

---

## Configuration Details

### JWT Settings

| Setting        | Description                           | Recommended Value |
|----------------|---------------------------------------|-------------------|
| Key            | Secret key for signing tokens         | 32+ characters    |
| Issuer         | Token issuer identifier               | Your domain       |
| Audience       | Token audience identifier             | Your app name     |
| ExpireMinutes  | Access token lifetime                 | 15 minutes        |

### Refresh Token Settings

- **Lifetime**: 7 days (configurable in code)
- **Rotation**: New token issued on each refresh
- **Storage**: Database table with user relationship
- **Cleanup**: Automated background service

---

## Security Best Practices Implemented

✅ **Short-lived access tokens** - Minimize exposure window  
✅ **Secure token generation** - Cryptographically random  
✅ **Refresh token rotation** - Prevents token reuse  
✅ **Token revocation** - Server-side session control  
✅ **Password hashing** - ASP.NET Core Identity defaults  
✅ **HTTPS enforcement** - Secure transport  
✅ **Role-based authorization** - Principle of least privilege  
✅ **No sensitive data in logs** - Privacy protection  
✅ **Automatic token cleanup** - Prevents database bloat  

---

## Identity Event Logging

The application logs critical security events:

- ✅ User registration
- ✅ Successful login attempts
- ❌ Failed login attempts
- 🔄 Token refresh operations
- 🚪 Logout events
- 🔒 Session revocations
- ⚠️ Suspicious activity indicators

Logs are useful for:
- Security auditing
- Compliance requirements
- Troubleshooting authentication issues
- Detecting unauthorized access attempts

---

## Usage Examples

### Register User
```bash
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "a1b2c3d4e5f6...",
  "expiresIn": 900
}
```

### Access Protected Endpoint
```bash
GET /api/secure
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### Refresh Token
```bash
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "a1b2c3d4e5f6..."
}
```

### Logout
```bash
POST /api/auth/logout
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Content-Type: application/json

{
  "refreshToken": "a1b2c3d4e5f6..."
}
```

---

## Technology Stack

- **.NET 8.0** - Framework
- **ASP.NET Core Identity** - User management
- **Entity Framework Core** - ORM
- **SQL Server** - Database
- **JWT Bearer Authentication** - Token validation
- **Hosted Services** - Background tasks

---

## License

This project is licensed under the MIT License.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## Support

For issues or questions, please open an issue on GitHub.

---

**Built with security and scalability in mind** 🔒
