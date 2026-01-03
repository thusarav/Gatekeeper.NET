using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// --------------------
// Services
// --------------------
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

// 🔐 Authorization Policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("authenticated", policy =>
        policy.RequireAuthenticatedUser());

    options.AddPolicy("admin-only", policy =>
        policy.RequireRole("Admin"));
});

// 🔁 YARP
builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

// --------------------
// Middleware
// --------------------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

// --------------------
// AUTH ENDPOINTS
// --------------------

// 🔐 LOGIN — Issue JWT (User default, Admin via ?role=Admin)
app.MapPost("/auth/login", (string? role, IConfiguration config) =>
{
    var userRole = string.IsNullOrEmpty(role) ? "User" : role;

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, "demo-user"),
        new Claim(ClaimTypes.Role, userRole)
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

    return Results.Ok(new
    {
        token = jwt,
        role = userRole
    });
});

// 🔍 INSPECT — Decode JWT (debug / learning only)
app.MapPost("/auth/inspect", (HttpContext context) =>
{
    var authHeader = context.Request.Headers.Authorization.ToString();

    if (!authHeader.StartsWith("Bearer "))
    {
        return Results.BadRequest(new
        {
            error = "Missing or invalid Authorization header"
        });
    }

    var token = authHeader["Bearer ".Length..].Trim();
    var handler = new JwtSecurityTokenHandler();
    var jwtToken = handler.ReadJwtToken(token);

    return Results.Ok(new
    {
        issuer = jwtToken.Issuer,
        audience = jwtToken.Audiences,
        issuedAt = jwtToken.IssuedAt,
        expiresAt = jwtToken.ValidTo,
        claims = jwtToken.Claims.Select(c => new { c.Type, c.Value })
    });
});

// --------------------
// YARP — 🔒 PROTECTED
// --------------------
app.MapReverseProxy()
   .RequireAuthorization("authenticated");

app.Run();
