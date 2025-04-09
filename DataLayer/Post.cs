using socset.Models;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace socset.DataLayer
{
    public class Post
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Content { get; set; }
        public DateTime CreatedAt { get; set; }
        //внеш ключ
        public int UserId {  get; set; }
        public ApplicationUser User { get; set; }
        public ICollection<Like> Likes { get; set; }
       /* [Key]

        public int Id { get; set; }

        public int AuthorId { get; set; }

        [ForeignKey("AuthorId")]

        public ApplicationUser Author { get; set; }

        public string Longitude { get; set; }

        public string Latitude { get; set; }

        public DateTime CreatedDate { get; set; } = DateTime.Now;

        public DateTime ModifiedDate { get; set; } = DateTime.Now;

        public int HobbyId { get; set; }

        [ForeignKey("HobbyId")]

        public Hobby Hobby { get; set; }

        public string Text { get; set; }*/
    }
}
