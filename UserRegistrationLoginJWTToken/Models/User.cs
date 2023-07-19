namespace UserRegistrationLoginJWTToken.Models
{
    public class User
    {
        public string Login { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
    }
}
