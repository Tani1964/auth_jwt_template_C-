using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualBasic;

namespace JwtAuth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    public static User user = new();

    [HttpPost("register")]
    public ActionResult<User> Register(UserDto request)
    {
        var PasswordHash = new PasswordHasher<User>().HashPassword(user, request.Password);

        user.Username = request.Username;
        user.PasswordHash = PasswordHash;

        return Ok(user);
    }
}
