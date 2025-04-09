using socset.DataLayer;
using System.ComponentModel.DataAnnotations.Schema;

namespace socset.Models
{
    public class Follow
    {
       
        public int Id { get; set; }
        public  int FollowerId { get; set; }

        public ApplicationUser Follower { get; set; }
        public int FolloweeId { get; set; }
        public ApplicationUser Followee { get; set; }

        /* 
        public string FollowingId { get; set; }


        [ForeignKey("FollowingId")]
        public virtual UserRepository Following { get; set; }

        [ForeignKey("FollowerId")]
        public virtual UserRepository Follower { get; set; }

        public DateTime CreateAt { get; set; } = DateTime.UtcNow;*/

    }
}
