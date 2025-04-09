using Microsoft.AspNetCore.Identity;
using socset.DataLayer;

namespace socset.Models
{
    public class UserRepository : IdentityUser
    {
        public string Name { get; set; }
        public string Avatar { get; set; }
        public ICollection<Post> Tweets { get; set; } = new List<Post>();
        public ICollection<Like> Likes { get; set; } = new List<Like>();


    }
}
