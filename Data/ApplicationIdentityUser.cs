using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace website.Data
{
    public class ApplicationIdentityUser : IdentityUser
    {

        public string CustomTag { get; set; }
    
    }
}