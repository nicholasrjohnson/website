using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace website.Models
{
    public class LoginWithRecoveryCodeModel
    {
        
        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        public class InputModel
        {
            [BindProperty]
            [Required]
            [DataType(DataType.Text)]
            [Display(Name = "Recovery Code")]
            public string RecoveryCode { get; set; }
        }


    }
}