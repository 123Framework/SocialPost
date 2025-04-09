using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using socset.DataLayer;
using socset.Models;
using socset.Repository;
using System.Security.Claims;

namespace socset.Controllers
{
    [Authorize]
    public class LikeController : Controller
    {
        private readonly ILikeRepository _likeRepository;
        private readonly IPostRepository _postRepository;
        private readonly UserManager<ApplicationUser> _userManager;
        public LikeController(ILikeRepository likeRepository, IPostRepository postRepository, UserManager<ApplicationUser>userManager)
        {
            _likeRepository = likeRepository;
            _postRepository = postRepository;
            _userManager = userManager;
        }
       
       

        public async Task<IActionResult> LikeTweet(int PostId)//addLike
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            
            var post = await _postRepository.GetByIdAsync(PostId);
            if (post == null) return NotFound();
             
            var isLiked = await _likeRepository.IsLikedAsync(user.Id, post.Id);
            if (!isLiked) { 
            var like = new Like { UserId = user.Id, PostId = PostId };
                await _likeRepository.AddLikeAsync(like);
            }
            



            return RedirectToAction("Index", "Post");

        }
        public async Task<IActionResult> UnlikeTweet(int postId)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            var like = await _likeRepository.GetLikeAsync(user.Id, postId);
            if (like != null) await _likeRepository.RemoveLikeAsync(like: like);

            return RedirectToAction("Index", "Post");
        }
    }
}
