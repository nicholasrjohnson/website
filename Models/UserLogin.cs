namespace website.Models
{
    public class UserLogin
    {
        public string UserId {get; set;} 
        public string LoginProvider { get; set; }
        public string ProviderKey {get; set;}
    }
}