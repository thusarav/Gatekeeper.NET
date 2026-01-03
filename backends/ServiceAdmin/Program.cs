var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/admin/health", () =>
{
    return Results.Ok(new
    {
        service = "ServiceAdmin",
        message = "Admin-only service is healthy"
    });
});

app.Run();
