public interface IAuthService
{
    Task<User?> RegisterAsync(UserDto userDto);
    Task<string?> LoginAsync(UserDto userDto);
}