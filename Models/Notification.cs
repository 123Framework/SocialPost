namespace socset.Models
{
    public class Notification
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public UserRepository User {  get; set; }
        public string Content { get; set; }
        public bool IsRead {  get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    }
}
