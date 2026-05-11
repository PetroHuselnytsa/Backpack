using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/protected")]
public class ProtectedController : ControllerBase
{
    // Any authenticated user can access this
    [Authorize]
    [HttpGet("user-data")]
    public IActionResult GetUserData()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                  ?? User.FindFirst("sub")?.Value;
        return Ok(new { message = "Hello, authenticated user!", userId });
    }

    // Only users with the "admin" role can access this
    [Authorize(Roles = "admin")]
    [HttpGet("admin-data")]
    public IActionResult GetAdminData()
    {
        return Ok(new { message = "Hello, admin! This is restricted data." });
    }
}
