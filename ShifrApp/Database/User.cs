using Microsoft.AspNetCore.Identity;

namespace ShifrApp.Database;

public class User : IdentityUser
{
    public string? Initials { get; set; }
}