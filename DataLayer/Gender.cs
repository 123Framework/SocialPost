using System.ComponentModel.DataAnnotations;

namespace socset.DataLayer
{
    public class Gender
    {
        [Key]

        public int Id { get; set; }

        public char GenderType { get; set; }
    }
}
