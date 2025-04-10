using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace socset.ViewModels
{
    public class RegisterVM
    {
        [Required]
        [EmailAddress]

        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "Password length must be at least 2 characters", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "The password and confirmation do not match")]
        public string ConfirmPassword { get; set; }

        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime DateOfBirth { get; set; }
        public int GenderId { get; set; }
    }
}
