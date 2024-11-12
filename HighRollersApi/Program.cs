using AutoMapper;
using HighRollersApi;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddDbContext<HighRollersDb>(x => x.UseSqlServer(builder.Configuration.GetConnectionString("")));

builder.Services.AddAutoMapper(typeof(StoreProfile));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("hashman"))
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
var mapper = app.Services.GetRequiredService<IMapper>();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();


app.MapPost("/signup", async (CustomerDto customerDto, HighRollersDb db, IMapper mapper) =>
{
    var customer = mapper.Map<Customer>(customerDto);
    db.Customers.Add(customer);
    await db.SaveChangesAsync();
    return Results.Ok("Customer signed up successfully");
});

app.MapPost("/admin/login", async (AdminDto adminDto, HighRollersDb db) =>
{
    var admin = db.Admins.FirstOrDefault(a => a.Username == adminDto.Username);
    if (admin == null || !BCrypt.Net.BCrypt.Verify(adminDto.Password, admin.PasswordHash))
    {
        return Results.Unauthorized();
    }

    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes("hashman");
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Role, "Admin") }),
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    var jwtToken = tokenHandler.WriteToken(token);

    return Results.Ok(new { Token = jwtToken });
});

// Add new admin (only accessible by admins)
app.MapPost("/admin/add", [Authorize(Policy = "AdminOnly")] async (AdminDto adminDto, HighRollersDb db, IMapper mapper) =>
{
    var admin = mapper.Map<Admin>(adminDto);
    admin.PasswordHash = BCrypt.Net.BCrypt.HashPassword(adminDto.Password); // Hash the password before storing
    db.Admins.Add(admin);
    await db.SaveChangesAsync();
    return Results.Ok("Admin added successfully");
});

// Edit an admin (only accessible by admins)
app.MapPut("/admin/edit/{id:int}", [Authorize(Policy = "AdminOnly")] async (int id, AdminDto adminDto, HighRollersDb db) =>
{
    var admin = await db.Admins.FindAsync(id);
    if (admin == null) return Results.NotFound();

    admin.Username = adminDto.Username;
    admin.PasswordHash = BCrypt.Net.BCrypt.HashPassword(adminDto.Password);
    await db.SaveChangesAsync();
    return Results.Ok("Admin edited successfully");
});

// Delete an admin (only accessible by admins)
app.MapDelete("/admin/delete/{id:int}", [Authorize(Policy = "AdminOnly")] async (int id, HighRollersDb db) =>
{
    var admin = await db.Admins.FindAsync(id);
    if (admin == null) return Results.NotFound();

    db.Admins.Remove(admin);
    await db.SaveChangesAsync();
    return Results.Ok("Admin deleted successfully");
});

app.MapGet("/customers", async (CustomerFilterDto filter, HighRollersDb db) =>
{
    // Start with all customers
    var query = db.Customers.AsQueryable();

    // Apply filters if they are not null
    if (!string.IsNullOrWhiteSpace(filter.Name))
        query = query.Where(c => c.Name.Contains(filter.Name));

    if (!string.IsNullOrWhiteSpace(filter.IdentificationNumber))
        query = query.Where(c => c.IdentificationNumber == filter.IdentificationNumber);

    if (!string.IsNullOrWhiteSpace(filter.CellNumber))
        query = query.Where(c => c.CellNumber == filter.CellNumber);

    // Execute query
    var customers = await query.ToListAsync();

    // Return not found if no customers matched the filter criteria
    return customers.Any() ? Results.Ok(customers) : Results.NotFound("No customers found with the specified criteria.");
});
app.Run();

