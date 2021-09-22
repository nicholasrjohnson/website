using Microsoft.AspNetCore.Mvc;

namespace website.Models
{
    public class ConfirmEmailModel
    {
        [TempData]
        public string StatusMessage { get; set; } 
    }
}