using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using nicksite.Models;

namespace nicksite.Controllers
{
    public class InnerSanctumController : Controller
    {


        [Authorize]
        public IActionResult InnerSanctumIndex() {

            return View();
        }

    }
}