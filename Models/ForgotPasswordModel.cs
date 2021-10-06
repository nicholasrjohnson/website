using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace website.Models
{
    public class ForgotPasswordModel
    {

        public ForgotPasswordModel() {
            Input = new InputModel();
        }
        
            [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }
        }
    }
}