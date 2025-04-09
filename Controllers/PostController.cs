using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using socset.DataLayer;
using socset.Repository;

namespace socset.Controllers
{
    public class PostController : Controller
    {
        private readonly IPostRepository _postRepository;
        private readonly UserManager<ApplicationUser> _UserManager;
        public PostController(IPostRepository PostRepository, UserManager<ApplicationUser> userManager)
        {
            _postRepository = PostRepository;
            _UserManager = userManager;
        }
        public async Task<IActionResult> Index()
        {
            var posts = await _postRepository.GetAllAsync();
            return View(posts);
        }
        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Post post)
        {
            if (ModelState.IsValid)
            {
                var user = await _UserManager.GetUserAsync(User);
                post.UserId = user.Id;
                post.CreatedAt = DateTime.UtcNow;
                await _postRepository.AddAsync(post);
                return RedirectToAction("Index");
            }
            return View(post);
        }
        public async Task<IActionResult> Edit(int id)
        {
            var post = await _postRepository.GetByIdAsync(id);

            if (post == null || post.UserId != int.Parse( _UserManager.GetUserId(User)))
            {
                return Forbid();
            }
            return View(post);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, Post post)
        {
            if (id != post.Id) return NotFound();
            var user = await _UserManager.GetUserAsync(User);
            if (post.UserId != user.Id) return Forbid();
            if (ModelState.IsValid) { 
            await _postRepository.UpdateAsync(post);
                return RedirectToAction("Index");
            }
            return View(post);
        }
        public async Task<IActionResult> Delete(int id)
        {
            var post = await (_postRepository.GetByIdAsync(id));

            if (post == null || post.UserId != int.Parse(_UserManager.GetUserId(User)))
            {
                return Forbid();
            }
            return View(post);
        }
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var post = await _postRepository.GetByIdAsync(id);
            if (post.UserId != int.Parse(_UserManager.GetUserId(User)))
            {
                return Forbid();
            }
            await _postRepository.DeleteAsync(id);
            return RedirectToAction("Index");
        }
    }
}
