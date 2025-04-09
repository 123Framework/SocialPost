using Elastic.Clients.Elasticsearch;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using socset.Models;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;


using Microsoft.IdentityModel.Tokens;
using socset.DataLayer;
using socset.ViewModels;
using Microsoft.AspNetCore.Authorization;
//[Convert]::ToBase64String((New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes(32))
namespace socset.Controllers
{ 


public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private ILogger<AccountController> _logger;

    public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }
        [AllowAnonymous]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register(RegisterVM model)
    {
        //if (ModelState.IsValid)
        //{
            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                DateOfBirth = model.DateOfBirth,
                DateCreated = DateTime.Now,
                DateModified = DateTime.Now,
                ActiveAccount = true,
                GenderId = model.GenderId, 
            };
            
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "User");
                await _signInManager.SignInAsync(user, isPersistent: false);
                _logger.LogInformation("User {Email} registered succesfully.", model.Email);
                return RedirectToAction("Index", "Home");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error.Description);
            }
            //}
            _logger.LogWarning("Model state isnt valid(or other error)");
        return View(model);
    }

    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginVM model)
    {
        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

            if (result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }

            ModelState.AddModelError("", "Invalid login attempt.");
        }
        return View(model);
    }

    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Index", "Home");
    }
}
/*{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            if (model == null)
            {
                return BadRequest("Invaluid user data");
            }
            var user = new UserRepository
            {
                UserName = model.Username,
                Email = model.Email,
                Name = model.Name,
                Avatar = model.Avatar ?? "default-profile-pic.png"

            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            var token = GenerateJwtToken(user);
            return Ok(new { message = "User register succesfully", UserId = user.Id, Token = token });
        }


        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {

                return Unauthorized("Invalid credentials");

            }
            Console.WriteLine("jwt key: " + "SuperSecretLongKey123!@#SuperSecretLongKey123!@#");
            var token = GenerateJwtToken((UserRepository)user);
            return Ok(new { Token = token });
        }




        private string GenerateJwtToken(UserRepository user)
        {
            var key = Encoding.UTF8.GetBytes("SuperSecretLongKey123!@#SuperSecretLongKey123!@#");

            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = "http://localhost:5000",
                Audience = "http://localhost:5000",
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256)
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }*/
}
