using Microsoft.EntityFrameworkCore;
using socset.DataLayer;
using socset.Models;
using socset.Repository;

namespace socset.Repository

{
    public class PostRepository : IPostRepository
    {
        private readonly AppDbContext _context;
        public PostRepository(AppDbContext context)
        {
            _context = context;
        }
        public async Task AddAsync(Post post)
        {
            _context.Post.Add(post);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(int id)
        {
            var post = await _context.Post.FindAsync(id);
            if (post != null) { 
            _context.Post.Remove(post);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<IEnumerable<Post>> GetAllAsync()
        {
            return await _context.Post.Include(p => p.User).ToListAsync();
        }

        public async Task<Post> GetByIdAsync(int id)
        {
            return await _context.Post.Include(p => p.User).FirstOrDefaultAsync(p => p.Id == id);
        }

        public async Task UpdateAsync(Post post)
        {
            _context.Post.Update(post);
            await _context.SaveChangesAsync();
        }
    }
}
