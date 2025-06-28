using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;

namespace JwtAuth.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IAuthService authService) : ControllerBase
{
    [HttpPost("register")]
    public ActionResult<User> Register(UserDto request)
    {
        var user = authService.RegisterAsync(request).Result;
        if (user == null)
        {
            return BadRequest("User already exists");
        }

        return Ok(user);
    }

    [HttpPost("login")]
    public ActionResult<string> Login(UserDto request)
    {
        var result = authService.LoginAsync(request);
        if (result is null)
        {
            return BadRequest("Invalid Credentials");
        }
        return Ok(result);
    }

    [HttpPost("refresh-token")]
    public ActionResult<TokenResponseDto> RefreshToken(RefreshTokenRequestDto request)
    {
        var response = authService.RefreshTokenAsync(request).Result;
        if (response is null)
        {
            return BadRequest("Invalid refresh token");
        }
        return Ok(response);
    }


    [Authorize]
    [HttpGet]
    public IActionResult AuthenticatedOnlyEndpoint()
    {
        if (!User.Identity.IsAuthenticated)
        {
            return Unauthorized();
        }

        return Ok("This is an authenticated endpoint");
    }

    [Authorize(Roles = "Admin")]
    [HttpGet("admin-only")]
    public IActionResult AdminOnly()
    {
        if (!User.Identity.IsAuthenticated)
        {
            return Unauthorized();
        }

        return Ok("This is an authenticated endpoint");
    }
}
