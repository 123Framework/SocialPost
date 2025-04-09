using Microsoft.EntityFrameworkCore;
using socset.DataLayer;
using socset.Models;


namespace socset.Repository
{
    public class FollowRepository : IFollowRepository
    {

        private readonly AppDbContext _appDbContext;

        public FollowRepository(AppDbContext appDbContext)
        {
            _appDbContext = appDbContext;
        }


        public async Task AddAsync(Follow follow)
        {
            _appDbContext.Follows.Add(follow);
            await _appDbContext.SaveChangesAsync();
        }

        public async Task<IEnumerable<ApplicationUser>> GetFollowersAsync(int userId)
        {
            return await _appDbContext.Follows.Where(f => f.FolloweeId == userId)
                .Select(f => f.Follower).ToListAsync();
        }

        public async Task<IEnumerable<ApplicationUser>> GetFollowingAsync(int userId)
        {
            return await _appDbContext.Follows.Where(f => f.FollowerId == userId)
                .Select(f => f.Followee).ToListAsync();
        }

        public async Task<bool> IsFollowingAsync(int followerId, int followeeId)
        {
            return await _appDbContext.Follows.AnyAsync(f => f.FollowerId == followerId && f.FolloweeId==followeeId);
        }

        public async Task RemoveAsync(Follow follow)
        {
            _appDbContext.Follows.Remove(follow);
            await _appDbContext.SaveChangesAsync();
        }
    }
}
