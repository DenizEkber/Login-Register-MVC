using System.ComponentModel.DataAnnotations;

namespace LoginRegister.Models
{
    public class User
    {
        public int Id { get; set; }

        [Required]
        public string Username { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        public string Hash { get; set; }
        public string Salt { get; set; }
    }
}
