using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

public class AuthService(UserDbContext context, IConfiguration configuration) : IAuthService
{
    public async Task<User?> RegisterAsync(UserDto request)
    {
        if (await context.Users.AnyAsync(u => u.Username == request.Username))
        {
            return null;
        }

        var user = new User();

        var PasswordHash = new PasswordHasher<User>().HashPassword(user, request.Password);

        user.Username = request.Username;
        user.PasswordHash = PasswordHash;

        context.Users.Add(user);
        await context.SaveChangesAsync();

        return user;
    }

    public async Task<TokenResponseDto?> LoginAsync(UserDto request)
    {
        var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        if (user == null)
        {
            return null;
        }

        var result = new PasswordHasher<User>().VerifyHashedPassword(
            user,
            user.PasswordHash,
            request.Password
        );
        if (result == PasswordVerificationResult.Failed)
        {
            return null;
        }

        var response = new TokenResponseDto
        {
            AccessToken = GenerateToken(user),
            RefreshToken = await GenerateAndSaveRefreshToken(user)
        };

        return response;
    }

    private async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken)
    {
        var user = await context.Users.FindAsync(userId); 
        if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime < DateTime.Now)
        {
            return null;
        }

        return user;
    }

    public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request)
    {
        var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
        if (user == null)
        {
            return null;
        }

        var newRefreshToken = await GenerateAndSaveRefreshToken(user);
        var accessToken = GenerateToken(user);

        return new TokenResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshToken
        };
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();

        rng.GetBytes(randomNumber);

        return Convert.ToBase64String(randomNumber);
    }
    
    private async Task<string> GenerateAndSaveRefreshToken(User user)
    {
        var refreshToken = GenerateRefreshToken();
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
        
        context.Users.Update(user);
        await context.SaveChangesAsync();
        
        return refreshToken;
    }

    // private string CreateRefreshToken(User user)
    // {
    //     var claims = new List<Claim>
    //     {
    //         new Claim(ClaimTypes.Name, user.Username),
    //         new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
    //         new Claim(ClaimTypes.Role, user.Role),
    //         new Claim("RefreshToken", GenerateRefreshToken())
    //     };
    // }

    private string GenerateToken(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Role, user.Role), // Assuming user has a Role property
        };

        var key = new SymmetricSecurityKey(
            System.Text.Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!)
        );
        return "GeneratedToken";

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var tokenDescriptor = new JwtSecurityToken(
            issuer: configuration.GetValue<string>("AppSettings:Issuer"),
            audience: configuration.GetValue<string>("AppSettings:Audience"),
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: creds
        );
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
    }
}
