using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System;
using System.ComponentModel.DataAnnotations;
using System.DirectoryServices;
using System.Security.Claims;
using System.Threading.Tasks;

namespace LDAP.Controllers
{
    public class LoginController : Controller
    {
        [HttpPost("/account/login")]
        public async Task<IActionResult> Login(UserCredentials credentials)
        {

            //The domain to look for our user
            string path = "LDAP://upstatesvr.upstatedoor.local/dc=upstatedoor,dc=local";

            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(path, credentials.UserName, credentials.Password))
                {
                    using (DirectorySearcher searcher = new DirectorySearcher(entry))
                    {
                        //Look for the SamAccountName
                        searcher.Filter = "(samaccountname=" + credentials.UserName + ")";
                        //Look for the user with the indicated account
                        var result = searcher.FindOne();
                        if (result != null)
                        {
                            string role = "";
                            //Check the user properties
                            ResultPropertyCollection fields = result.Properties;
                            foreach (string ldapField in fields.PropertyNames)
                            {
                                foreach (Object myCollection in fields[ldapField])
                                {
                                    if (ldapField == "sAMAccountName")//userPrincipalName
                                    {
                                        role = myCollection.ToString().ToLower();
                                    }
                                }
                            }

                            //Add the User and Role claims to have them available in the Cookie
                            //We could get them from a database
                            var claims = new[]
                            {
                                new Claim(ClaimTypes.Name, credentials.UserName),
                                new Claim(ClaimTypes.Role, role)
                            };

                            //Create the main
                            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

                            //Generate the cookie, SignInAsync is a context extension method
                            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);

                            //Redirect home
                            return LocalRedirect("/");
                        }
                        else
                        {
                            return LocalRedirect("/login/invalid credentials");
                        }
                    }
                }
            }
            catch
            {
                return LocalRedirect("/login/Invalid Credentials");
            }
        }
        [HttpGet("/account/logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return LocalRedirect("/");
        }   
    }

    public class UserCredentials
    { 
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
