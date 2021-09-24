using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using website.Models;

namespace website.Controllers
{
    public class InnerSanctumController : Controller
    {

            [Authorize]
        public IActionResult InnerSanctumIndex() {

            return View();
        }

    }
}