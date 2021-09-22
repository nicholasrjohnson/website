using Microsoft.AspNetCore.Mvc;

namespace website.Models
{
    public class ResetAuthenticatorModel
    {
        [TempData]
        public string StatusMessage { get; set; }
    }
}