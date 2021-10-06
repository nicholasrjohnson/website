using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using website.Models;
using website.Data;

namespace website.Controllers
{
    public class AdminController : Controller
    {
       
        private readonly UserManager<ApplicationIdentityUser> _userManager;
        private readonly SignInManager<ApplicationIdentityUser> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;
        private readonly UrlEncoder _urlEncoder;
        private readonly IEmailSender _emailSender;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        public AdminController(
            UserManager<ApplicationIdentityUser> userManager,
            SignInManager<ApplicationIdentityUser> signInManager,
            ILogger<ChangePasswordModel> logger,
            IEmailSender emailSender,
            UrlEncoder urlEncoder,
            IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _urlEncoder = urlEncoder;
            _httpContextAccessor = httpContextAccessor;
        } 

        public IActionResult AdminIndex(AdminIndexModel model) {
            model = new AdminIndexModel();
            return View(model); 
        }

        public async Task<IActionResult> ChangePassword()
        {
            ChangePasswordModel model = new ChangePasswordModel();

            if (!ModelState.IsValid)
            {
                return View();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (!hasPassword)
            {
                return View("~/Admin/SetPassword");
            }

            var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.Input.OldPassword, model.Input.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                foreach (var error in changePasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View();
            }

            await _signInManager.RefreshSignInAsync(user);
            _logger.LogInformation("User changed their password successfully.");
            model.StatusMessage = "Your password has been changed.";

            return View(model);
        }
        public async Task<IActionResult> GetSetPasswordAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var hasPassword = await _userManager.HasPasswordAsync(user);

            if (hasPassword)
            {
                return RedirectToPage("./ChangePassword");
            }

            return View();
        }

        public async Task<IActionResult> PostSetPasswordAsync()
        {
            SetPasswordModel model = new SetPasswordModel();

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var addPasswordResult = await _userManager.AddPasswordAsync(user, model.Input.NewPassword);
            if (!addPasswordResult.Succeeded)
            {
                foreach (var error in addPasswordResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                return View(model);
            }

            await _signInManager.RefreshSignInAsync(user);
            model.StatusMessage = "Your password has been set.";

            return View(model);
        }

        public async Task<IActionResult> GetDeletePersonalDataAsync()
        {
            DeletePersonalDataModel model = new DeletePersonalDataModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            model.RequirePassword = await _userManager.HasPasswordAsync(user);
            return View();
        }

        public async Task<IActionResult> PostDeletePersonalDataAsync()
        {
            DeletePersonalDataModel model = new DeletePersonalDataModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            model.RequirePassword = await _userManager.HasPasswordAsync(user);
            if (model.RequirePassword)
            {
                if (!await _userManager.CheckPasswordAsync(user, model.Input.Password))
                {
                    ModelState.AddModelError(string.Empty, "Incorrect password.");
                    return View();
                }
            }

            var result = await _userManager.DeleteAsync(user);
            var userId = await _userManager.GetUserIdAsync(user);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"Unexpected error occurred deleting user with ID '{userId}'.");
            }

            await _signInManager.SignOutAsync();

            _logger.LogInformation("User with ID '{UserId}' deleted themselves.", userId);

            return Redirect("~/");
        }


        public async Task<IActionResult> GetDisable2FAAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!await _userManager.GetTwoFactorEnabledAsync(user))
            {
                throw new InvalidOperationException($"Cannot disable 2FA for user with ID '{_userManager.GetUserId(User)}' as it's not currently enabled.");
            }

            return View();
        }

        public async Task<IActionResult> PostDisable2FAAsync()
        {
            Disable2FAModel model = new Disable2FAModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var disable2faResult = await _userManager.SetTwoFactorEnabledAsync(user, false);
            if (!disable2faResult.Succeeded)
            {
                throw new InvalidOperationException($"Unexpected error occurred disabling 2FA for user with ID '{_userManager.GetUserId(User)}'.");
            }

            _logger.LogInformation("User with ID '{UserId}' has disabled 2fa.", _userManager.GetUserId(User));
            model.StatusMessage = "2fa has been disabled. You can reenable 2fa when you setup an authenticator app";
            return RedirectToPage("./TwoFactorAuthentication");
        }
        
        public async Task<IActionResult> DownloadPersonalDataAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            _logger.LogInformation("User with ID '{UserId}' asked for their personal data.", _userManager.GetUserId(User));

            // Only include personal data for download
            var personalData = new Dictionary<string, string>();
            var personalDataProps = typeof(IdentityUser).GetProperties().Where(
                            prop => Attribute.IsDefined(prop, typeof(PersonalDataAttribute)));
            foreach (var p in personalDataProps)
            {
                personalData.Add(p.Name, p.GetValue(user)?.ToString() ?? "null");
            }

            var logins = await _userManager.GetLoginsAsync(user);
            foreach (var l in logins)
            {
                personalData.Add($"{l.LoginProvider} external login provider key", l.ProviderKey);
            }

            Response.Headers.Add("Content-Disposition", "attachment; filename=PersonalData.json");
            return new FileContentResult(JsonSerializer.SerializeToUtf8Bytes(personalData), "application/json");
        }

        private async Task<ChangeEmailModel> LoadEmailAsync(ApplicationIdentityUser user)
        {
            ChangeEmailModel model = new ChangeEmailModel();

            var email = await _userManager.GetEmailAsync(user);
            model.Email = email;

            model.Input = new ChangeEmailModel.InputModel
            {
                NewEmail = email,
            };

            model.IsEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);

            return model;
        }

        public async Task<IActionResult> ChangeEmail()
        {
            ChangeEmailModel model = new ChangeEmailModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!ModelState.IsValid)
            {
                model = await LoadEmailAsync(user);
                return View(model);
            }

            var email = await _userManager.GetEmailAsync(user);
            if (model.Input.NewEmail != email)
            {
                var userId = await _userManager.GetUserIdAsync(user);
                var code = await _userManager.GenerateChangeEmailTokenAsync(user, model.Input.NewEmail);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Page(
                    "/Account/ConfirmEmailChange",
                    pageHandler: null,
                    values: new { userId = userId, email = model.Input.NewEmail, code = code },
                    protocol: Request.Scheme);
                await _emailSender.SendEmailAsync(
                    model.Input.NewEmail,
                    "Confirm your email",
                    $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                model.StatusMessage = "Confirmation link to change email sent. Please check your email.";
                return View(model);
            }

            model.StatusMessage = "Your email is unchanged.";
            return View(model);
        }

        public async Task<IActionResult> OnPostSendVerificationEmailAsync()
        {
            ChangeEmailModel model = new ChangeEmailModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!ModelState.IsValid)
            {
                model = await LoadEmailAsync(user);
                return View(model);
            }

            var userId = await _userManager.GetUserIdAsync(user);
            var email = await _userManager.GetEmailAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var callbackUrl = Url.Page(
                "/Account/ConfirmEmail",
                pageHandler: null,
                values: new { area = "Identity", userId = userId, code = code },
                protocol: Request.Scheme);
            await _emailSender.SendEmailAsync(
                email,
                "Confirm your email",
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            model.StatusMessage = "Verification email sent. Please check your email.";
            return View(model);
        }

        
        private async Task<AdminIndexModel> LoadAdminIndexAsync(ApplicationIdentityUser user)
        {
            AdminIndexModel model = new AdminIndexModel();

            var userName = await _userManager.GetUserNameAsync(user);
            var phoneNumber = await _userManager.GetPhoneNumberAsync(user);

            model.Username = userName;

            model.Input = new AdminIndexModel.InputModel
            {
                PhoneNumber = phoneNumber
            };

            return model;
        }

        public async Task<IActionResult> GetAdminIndexAsync()
        {
            AdminIndexModel model = null;
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            model = await LoadAdminIndexAsync(user);
            return View(model);
        }

        public async Task<IActionResult> PostAdminIndexAsync()
        {
            AdminIndexModel model = new AdminIndexModel();
        
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!ModelState.IsValid)
            {
                model = await LoadAdminIndexAsync(user);
                return View(model);
            }

            var phoneNumber = await _userManager.GetPhoneNumberAsync(user);
            if (model.Input.PhoneNumber != phoneNumber)
            {
                var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, model.Input.PhoneNumber);
                if (!setPhoneResult.Succeeded)
                {
                    model.StatusMessage = "Unexpected error when trying to set phone number.";
                    return View(model);
                }
            }

            await _signInManager.RefreshSignInAsync(user);
            model.StatusMessage = "Your profile has been updated";
            return View(model);
        }

      public async Task<IActionResult> GetEnableAuthenticatorAsync()
        {
            EnableAuthenticatorModel model = new EnableAuthenticatorModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            model = await LoadSharedKeyAndQrCodeUriAsync(user, model);

            return View(model);
        }

        public async Task<IActionResult> PostEnableAuthenticatorAsync()
        {
            EnableAuthenticatorModel model = new EnableAuthenticatorModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            if (!ModelState.IsValid)
            {
                model = await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return View(model);
            }

            // Strip spaces and hypens
            var verificationCode = model.Input.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

            if (!is2faTokenValid)
            {
                ModelState.AddModelError("Input.Code", "Verification code is invalid.");
                model = await LoadSharedKeyAndQrCodeUriAsync(user, model);
                return View(model);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            var userId = await _userManager.GetUserIdAsync(user);
            _logger.LogInformation("User with ID '{UserId}' has enabled 2FA with an authenticator app.", userId);

            model.StatusMessage = "Your authenticator app has been verified.";

            if (await _userManager.CountRecoveryCodesAsync(user) == 0)
            {
                var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                model.RecoveryCodes = recoveryCodes.ToArray();
                return RedirectToPage("./ShowRecoveryCodes");
            }
            else
            {
                return RedirectToPage("./TwoFactorAuthentication");
            }
        }

        private async Task<EnableAuthenticatorModel> LoadSharedKeyAndQrCodeUriAsync(ApplicationIdentityUser user, EnableAuthenticatorModel model)
        {
            // Load the authenticator key & QR code URI to display on the form
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            model.SharedKey = FormatKey(unformattedKey);

            var email = await _userManager.GetEmailAsync(user);
            model.AuthenticatorUri = GenerateQrCodeUri(email, unformattedKey);

            return model;
        }

        private string FormatKey(string unformattedKey)
        {
            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.Substring(currentPosition));
            }

            return result.ToString().ToLowerInvariant();
        }

        private string GenerateQrCodeUri(string email, string unformattedKey)
        {
            return string.Format(
                AuthenticatorUriFormat,
                _urlEncoder.Encode("scaffold"),
                _urlEncoder.Encode(email),
                unformattedKey);
        }
        
        public async Task<IActionResult> GetExternalLoginsAsync()
        {
            ExternalLoginsModel model = new ExternalLoginsModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID 'user.Id'.");
            }

            model.CurrentLogins = await _userManager.GetLoginsAsync(user);
            model.OtherLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync())
                .Where(auth => model.CurrentLogins.All(ul => auth.Name != ul.LoginProvider))
                .ToList();
            model.ShowRemoveButton = user.PasswordHash != null || model.CurrentLogins.Count > 1;
            return View(model);
        }

        public async Task<IActionResult> PostRemoveLoginAsync(string loginProvider, string providerKey)
        {
            ExternalLoginsModel model = new ExternalLoginsModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID 'user.Id'.");
            }

            var result = await _userManager.RemoveLoginAsync(user, loginProvider, providerKey);
            if (!result.Succeeded)
            {
                model.StatusMessage = "The external login was not removed.";
                return View(model);
            }

            await _signInManager.RefreshSignInAsync(user);
            model.StatusMessage = "The external login was removed.";
            return View(model);
        }

        public async Task<IActionResult> PostLinkLoginAsync(string provider)
        {
            // Clear the existing external cookie to ensure a clean login process
            await _httpContextAccessor.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            // Request a redirect to the external login provider to link a login for the current user
            var redirectUrl = Url.Page("./ExternalLogins", pageHandler: "LinkLoginCallback");
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl, _userManager.GetUserId(User));
            return new ChallengeResult(provider, properties);
        }

        public async Task<IActionResult> GetLinkLoginCallbackAsync()
        {
            ExternalLoginsModel model = new ExternalLoginsModel();

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID 'user.Id'.");
            }

            var info = await _signInManager.GetExternalLoginInfoAsync(user.Id);
            if (info == null)
            {
                throw new InvalidOperationException($"Unexpected error occurred loading external login info for user with ID '{user.Id}'.");
            }

            var result = await _userManager.AddLoginAsync(user, info);
            if (!result.Succeeded)
            {
                model.StatusMessage = "The external login was not added. External logins can only be associated with one account.";
                return View(model);
            }

            // Clear the existing external cookie to ensure a clean login process
            await _httpContextAccessor.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            model.StatusMessage = "The external login was added.";
            return View(model);
        }

        public async Task<IActionResult> GetGenerateRecoveryCodesAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            if (!isTwoFactorEnabled)
            {
                var userId = await _userManager.GetUserIdAsync(user);
                throw new InvalidOperationException($"Cannot generate recovery codes for user with ID '{userId}' because they do not have 2FA enabled.");
            }

            return View();
        }

        public async Task<IActionResult> PostGenerateRecoveryCodesAsync()
        {
            GenerateRecoveryCodesModel model = new GenerateRecoveryCodesModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            var userId = await _userManager.GetUserIdAsync(user);
            if (!isTwoFactorEnabled)
            {
                throw new InvalidOperationException($"Cannot generate recovery codes for user with ID '{userId}' as they do not have 2FA enabled.");
            }

            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            model.RecoveryCodes = recoveryCodes.ToArray();

            _logger.LogInformation("User with ID '{UserId}' has generated new 2FA recovery codes.", userId);
            model.StatusMessage = "You have generated new recovery codes.";
            return RedirectToAction("GetShowRecovertyCodes", model);
        }

        public async Task<IActionResult> GetPersonalData()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            return View();
        }

        public async Task<IActionResult> ResetAuthenticator()
        {
            ResetAuthenticatorModel model = new ResetAuthenticatorModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            _logger.LogInformation("User with ID '{UserId}' has reset their authentication app key.", user.Id);
            
            await _signInManager.RefreshSignInAsync(user);
            model.StatusMessage = "Your authenticator app key has been reset, you will need to configure your authenticator app using the new key.";

            return RedirectToPage("./EnableAuthenticator");
        }

        public IActionResult GetShowRecoveryCodes(GenerateRecoveryCodesModel genmodel)
        {
            ShowRecoveryCodesModel model = new ShowRecoveryCodesModel();

            model.RecoveryCodes = new string[genmodel.RecoveryCodes.Count()];


            if (model.RecoveryCodes == null || model.RecoveryCodes.Length == -1)
            {
                return RedirectToPage("./TwoFactorAuthentication");
            }

            return View(model);
        }

        public async Task<IActionResult> GetTwoFactorAuthentication()
        {
            TwoFactorAuthenticationModel model = new TwoFactorAuthenticationModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            model.HasAuthenticator = await _userManager.GetAuthenticatorKeyAsync(user) != null;
            model.Is2faEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            model.IsMachineRemembered = await _signInManager.IsTwoFactorClientRememberedAsync(user);
            model.RecoveryCodesLeft = await _userManager.CountRecoveryCodesAsync(user);

            return View(model);
        }

        public async Task<IActionResult> OnTwoFactorAuthenticationPost()
        {
            TwoFactorAuthenticationModel model = new TwoFactorAuthenticationModel();
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
            }

            await _signInManager.ForgetTwoFactorClientAsync();
            model.StatusMessage = "The current browser has been forgotten. When you login again from this browser you will be prompted for your 2fa code.";
            return View(model);
        }
    }
}