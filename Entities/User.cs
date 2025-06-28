public class User
{

    public Guid Id { get; set; } = Guid.NewGuid();
    public String Username { get; set; } = string.Empty;
    public String PasswordHash { get; set; } = string.Empty;

    public string Role { get; set; } = "User";

    public string? RefreshToken { get; set; } = string.Empty;
    public DateTime RefreshTokenExpiryTime { get; set; } = DateTime.Now.AddDays(1);
}
