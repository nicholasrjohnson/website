using Microsoft.AspNetCore.Mvc;

namespace website.Models
{
    public class ShowRecoveryCodesModel
    {

        [TempData]
        public string[] RecoveryCodes { get; set; }

        [TempData]
        public string StatusMessage { get; set; }

    }
}