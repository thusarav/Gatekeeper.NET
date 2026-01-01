using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// 🔐 JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)
            )
        };
    });

builder.Services.AddAuthorization();

// YARP
builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

// Middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// DO NOT force HTTPS in dev
// app.UseHttpsRedirection();

// 🔐 Enable authentication & authorization
app.UseAuthentication();
app.UseAuthorization();

// Reverse proxy
app.MapReverseProxy()
    .RequireAuthorization(); // 🔒 Protect all YARP routes

// 🔐 LOGIN ENDPOINT (JWT ISSUER)
app.MapPost("/auth/login", (IConfiguration config) =>
{
    var claims = new[]
    {
        new Claim(ClaimTypes.Name, "demo-user"),
        new Claim(ClaimTypes.Role, "User")
    };

    var key = new SymmetricSecurityKey(
        Encoding.UTF8.GetBytes(config["Jwt:Key"]!)
    );

    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: config["Jwt:Issuer"],
        audience: config["Jwt:Audience"],
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(
            int.Parse(config["Jwt:ExpiresMinutes"]!)
        ),
        signingCredentials: creds
    );

    var jwt = new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new { token = jwt });
});

// 🔍 INSPECT ENDPOINT (DECODE JWT)
app.MapPost("/auth/inspect", (HttpContext context) =>
{
    try
    {
        // Extract token from Authorization header
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
        {
            return Results.BadRequest(new { error = "Missing or invalid Authorization header. Use: Authorization: Bearer YOUR_TOKEN" });
        }

        var token = authHeader.Substring("Bearer ".Length).Trim();
        var handler = new JwtSecurityTokenHandler();

        // Decode WITHOUT validation (just to inspect)
        var jwtToken = handler.ReadJwtToken(token);

        var claims = jwtToken.Claims.ToDictionary(c => c.Type, c => c.Value);

        return Results.Ok(new
        {
            message = "✅ JWT decoded successfully",
            token = token.Substring(0, 20) + "...", // Show first 20 chars
            issuer = jwtToken.Issuer,
            audience = string.Join(", ", jwtToken.Audiences),
            issuedAt = jwtToken.IssuedAt,
            expiresAt = jwtToken.ValidTo,
            expiresIn = (jwtToken.ValidTo - DateTime.UtcNow).TotalSeconds + " seconds",
            claims = claims
        });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = $"Invalid token: {ex.Message}" });
    }
});

app.Run();
