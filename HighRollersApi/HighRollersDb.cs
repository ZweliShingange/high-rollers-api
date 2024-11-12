using HighRollersApi;
using Microsoft.EntityFrameworkCore;

public class HighRollersDb:DbContext
{
    public HighRollersDb(DbContextOptions options) : base(options)
    {
    }

    public DbSet<Customer> Customers { get; set; }
    public DbSet<Admin> Admins { get; set; }
}