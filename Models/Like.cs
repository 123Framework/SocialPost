using socset.DataLayer;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace socset.Models
{
    public class Like
    {
        public int UserId { get; set; }
        public int Id { get; set; }
        public ApplicationUser User { get; set; }

        public int PostId { get; set; }
        public Post Post { get; set; }
        /*public int TweetId { get; set; }


        [ForeignKey("TweetId")]
        [JsonIgnore]

        public virtual Post Tweet { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;


        public string UserId { get; set; }


        [JsonIgnore]
        [ForeignKey("UserId")]
        public virtual UserRepository User { get; set; }
        */


    }
}
