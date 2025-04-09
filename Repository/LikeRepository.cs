

using socset.Models;

using socset.ViewModels;
using Elastic.Clients.Elasticsearch.QueryDsl;
using Microsoft.EntityFrameworkCore;

namespace socset.Repository
{
    public class LikeRepository : ILikeRepository
    {
        private readonly AppDbContext _context;

        public LikeRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task AddLikeAsync(Models.Like like)
        {
            _context.Likes.Add(like);
            await _context.SaveChangesAsync();
        }

        public async Task<Models.Like> GetLikeAsync(int userId, int postId)
        {
            return await _context.Likes.FirstOrDefaultAsync( I => I.UserId == userId && I.PostId == postId);
        }

        public async Task<int> GetLikeCountAsync(int postId)
        {
            return await _context.Likes.CountAsync(I => I.PostId == postId);

        }

        public async Task<bool> IsLikedAsync(int userId, int postId)
        {
            return await _context.Likes.AnyAsync(I => I.UserId == userId && I.PostId == postId);

        }

        public async Task RemoveLikeAsync(Models.Like like)
        {
            _context.Likes.Remove(like);
            await _context.SaveChangesAsync();
        }

        
    }
}
