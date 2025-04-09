using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace socset.Controllers
{
   // [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class ProfileController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetProfile()
        {
            var userId = User.Claims.First(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
            return Ok(new { Message = "Welcome, your ID:" + userId });
        }


    }
}
