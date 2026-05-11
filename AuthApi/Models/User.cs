namespace AuthApi.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Email { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>Role is either "admin" or "user".</summary>
    public string Role { get; set; } = "user";

    public ICollection<RefreshToken> RefreshTokens { get; set; } = [];
}
