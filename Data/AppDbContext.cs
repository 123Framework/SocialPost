namespace socset.Models;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using socset.DataLayer;

public class AppDbContext : IdentityDbContext<ApplicationUser,IdentityRole<int>,int>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }
       // public DbSet<Hobby> Hobby { get; set; }

   // public DbSet<HobbyCategory> HobbyCategory { get; set; }

 //   public DbSet<Gender> Gender { get; set; }

    //public DbSet<City> City { get; set; }

   // public DbSet<Country> Country { get; set; }

  //  public DbSet<ApplicationUser> Users { get; set; }

   // public DbSet<FriendshipStatus> FriendshipStatus { get; set; }

    //public DbSet<Friendship> Friendship { get; set; }

    //public DbSet<ApplicationUserHobby> ApplicationUserHobbies { get; set; }

    public DbSet<Post> Post { get; set; }

    //public DbSet<NotificationType> NotificationType { get; set; }

   // public DbSet<BellNotification> BellNotification { get; set; }

   // public DbSet<Skill> Skill { get; set; }

    public DbSet<Follow> Follows { get; set; }

    public DbSet<Like> Likes {  get; set; } 

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<Follow>().HasOne(f => f.Follower).WithMany().HasForeignKey(f => f.FollowerId).OnDelete(DeleteBehavior.Restrict);
        modelBuilder.Entity<Follow>().HasOne(f => f.Followee).WithMany().HasForeignKey(f => f.FolloweeId).OnDelete(DeleteBehavior.Restrict);
        modelBuilder.Entity<Like>().HasOne(f => f.User).WithMany().HasForeignKey(f => f.UserId).OnDelete(DeleteBehavior.Restrict);
        modelBuilder.Entity<Like>().HasOne(f => f.Post).WithMany().HasForeignKey(f => f.PostId).OnDelete(DeleteBehavior.Restrict);

    }
}
   
    

           

