
using socset.Models;


namespace socset.Repository
{
    public interface ILikeRepository 
    {
        Task<bool> IsLikedAsync(int userId, int postId);
        Task<int> GetLikeCountAsync(int postId);
        Task AddLikeAsync(Like like);
        Task RemoveLikeAsync(Like like);
        Task<Like> GetLikeAsync(int userId, int postId);
    }
}
