using Microsoft.AspNetCore.Identity;

namespace IdentityLoggerDemo.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? FullName { get; set; }
    }
}
