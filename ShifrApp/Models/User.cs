using Microsoft.AspNetCore.Identity;

namespace ShifrApp.Database;

public class user : IdentityUser
{
    public string? Initiasls { get; set; }
}