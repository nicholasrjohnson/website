using Microsoft.AspNetCore.Mvc;

namespace website.Models
{
    public class ConfirmEmailChangeModel
    {
       
        [TempData]
        public string StatusMessage { get; set;  
    }
}