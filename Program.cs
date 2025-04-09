using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using socset.Models;
using System.Data.Common;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using NToastNotify;
using socset.Repository;
using socset.DataLayer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>

    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole<int>>(options =>

{

    options.SignIn.RequireConfirmedEmail = false; options.Password.RequiredLength = 6;

    options.Password.RequireDigit = false;

    options.Password.RequireUppercase = false;

    options.Password.RequireLowercase = true;

    options.Lockout.MaxFailedAccessAttempts = 5;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(3);

}).AddEntityFrameworkStores<AppDbContext>()

.AddDefaultTokenProviders();

/*.AddPasswordValidator<CommonPasswordValidator<UserRepository>>();*/

builder.Services.ConfigureApplicationCookie(config =>

{

    config.Cookie.Name = "MyCookie";

    config.LoginPath = "/Account/Login";

    config.AccessDeniedPath = "/Account/AccessDenied";

});


builder.Services.AddScoped<IPostRepository, PostRepository>();

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

builder.Services.AddScoped<ILikeRepository, LikeRepository>();

builder.Services.AddScoped<IFollowRepository, FollowRepository>();

builder.Services.AddMemoryCache();

builder.Services.AddAutoMapper(typeof(Program));

builder.Services.AddControllersWithViews()

    .AddRazorRuntimeCompilation()

    .AddNToastNotifyNoty(new NotyOptions()

    {

        ProgressBar = true,

        Timeout = 5000,

        Theme = "sunset"

    });

builder.Services.AddRazorPages();

builder.Services.AddSignalR();



var app = builder.Build();

app.UseNToastNotify();

if (app.Environment.IsDevelopment())

{

    app.UseDeveloperExceptionPage();

}

else

{

    app.UseExceptionHandler("/Error");

    app.UseHsts();

}
app.UseHttpsRedirection();

app.UseStaticFiles();



app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();



app.UseCors(builder => builder

    .AllowAnyOrigin()

    .AllowAnyMethod()

    .AllowAnyHeader()

);

app.UseEndpoints(endpoints =>

{

    endpoints.MapControllerRoute(

        name: "default",

        pattern: "{controller=Home}/{action=Index}/{id?}");

   /* endpoints.MapHub<ChatHub>("/chathub");

    endpoints.MapHub<NotificationHubUser>("/NotificationUserHub");*/

});



app.Run();