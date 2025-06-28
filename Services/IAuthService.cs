public interface IAuthService
{
    Task<User?> RegisterAsync(UserDto userDto);
    Task<TokenResponseDto?> LoginAsync(UserDto userDto);
    Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request); 
}