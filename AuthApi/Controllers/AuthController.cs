using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly ITokenService _tokenService;
    private readonly IConfiguration _config;

    public AuthController(AppDbContext db, ITokenService tokenService, IConfiguration config)
    {
        _db = db;
        _tokenService = tokenService;
        _config = config;
    }

    // POST /api/auth/register
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (await _db.Users.AnyAsync(u => u.Email == request.Email))
            return Conflict(new { message = "Email already in use." });

        // Restrict role assignment: only "user" or "admin" allowed
        var roleLower = request.Role.ToLower();
        var role = roleLower is "admin" or "user" ? roleLower : "user";

        var user = new User
        {
            Email = request.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            Role = role
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        return Ok(new { message = "User registered successfully.", userId = user.Id });
    }

    // POST /api/auth/login
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

        if (user is null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            return Unauthorized(new { message = "Invalid email or password." });

        var accessToken = _tokenService.GenerateAccessToken(user);
        var (refreshTokenValue, refreshToken) = CreateRefreshToken(user.Id);

        _db.RefreshTokens.Add(refreshToken);
        await _db.SaveChangesAsync();

        return Ok(new AuthResponse(accessToken, refreshTokenValue));
    }

    // POST /api/auth/refresh
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        var storedToken = await _db.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

        if (storedToken is null || storedToken.IsRevoked || storedToken.Expiry < DateTime.UtcNow)
            return Unauthorized(new { message = "Invalid or expired refresh token." });

        // Revoke old token (rotation)
        storedToken.IsRevoked = true;

        // Issue new token pair
        var newAccessToken = _tokenService.GenerateAccessToken(storedToken.User);
        var (newRefreshTokenValue, newRefreshToken) = CreateRefreshToken(storedToken.UserId);

        _db.RefreshTokens.Add(newRefreshToken);
        await _db.SaveChangesAsync();

        return Ok(new AuthResponse(newAccessToken, newRefreshTokenValue));
    }

    // POST /api/auth/revoke
    [HttpPost("revoke")]
    public async Task<IActionResult> Revoke([FromBody] RevokeRequest request)
    {
        var storedToken = await _db.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

        if (storedToken is null)
            return NotFound(new { message = "Refresh token not found." });

        storedToken.IsRevoked = true;
        await _db.SaveChangesAsync();

        return Ok(new { message = "Token revoked." });
    }

    private (string value, RefreshToken token) CreateRefreshToken(int userId)
    {
        var tokenValue = _tokenService.GenerateRefreshToken();
        var expiryDays = int.Parse(_config["JwtSettings:RefreshTokenExpiryDays"] ?? "7");
        var token = new RefreshToken
        {
            Token = tokenValue,
            Expiry = DateTime.UtcNow.AddDays(expiryDays),
            UserId = userId
        };
        return (tokenValue, token);
    }
}
