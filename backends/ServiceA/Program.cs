var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// NO HTTPS
// NO JWT
// NO YARP
// NO CONTROLLERS

app.MapGet("/hello", () =>
{
    return Results.Ok(new
    {
        service = "Service A",
        message = "Hello from backend service A"
    });
});

app.Run();
