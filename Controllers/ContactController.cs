using System;
using System.Linq;
using website.Models;
using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace website.Controllers
{
    public class ContactController
    {
        IConfiguration _configuration;
       ContactController( IConfiguration configuration ) {
           _configuration = configuration;
       } 

       async bool sendEmail( Email email ) {
           int port;
           int.TryParse(_configuration["Smtp:Port"], out port);
           var smtpClient = new SmtpClient(_configuration["Smtp:Host"])
           {
                Port = port,
                Credentials = new NetworkCredential(_configuration["Smtp:Username"],_configuration["Smtp:Password"] ), 
                EnableSsl = true,
            };
       }
    }
}