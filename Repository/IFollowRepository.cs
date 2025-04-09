
using socset.DataLayer;
using socset.Models;

namespace socset.Repository
{
    public interface IFollowRepository
    {
        Task<bool> IsFollowingAsync(int followerId, int followeeId);
        Task<IEnumerable<ApplicationUser>> GetFollowersAsync(int userId);
        Task<IEnumerable<ApplicationUser>> GetFollowingAsync(int userId);
        Task AddAsync(Follow follow);
        Task RemoveAsync(Follow follow);
    }
}
