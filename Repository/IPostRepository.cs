using socset.DataLayer;
using System.Collections.Generic;
using System.Threading.Tasks;
namespace socset.Repository
{
    public interface IPostRepository
    {
        Task<Post> GetByIdAsync(int id);
        Task<IEnumerable<Post>> GetAllAsync();
        Task AddAsync(Post post);
        Task UpdateAsync(Post post);
        Task DeleteAsync(int id);

    }
}

