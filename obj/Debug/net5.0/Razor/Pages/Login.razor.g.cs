#pragma checksum "C:\Users\lhotchkiss\source\repos\LDAP\Pages\Login.razor" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "234419825285d850842763e703fc54ff9bbaceb2"
// <auto-generated/>
#pragma warning disable 1591
namespace LDAP.Pages
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Components;
#nullable restore
#line 1 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using System.Net.Http;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using Microsoft.AspNetCore.Authorization;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using Microsoft.AspNetCore.Components.Authorization;

#line default
#line hidden
#nullable disable
#nullable restore
#line 4 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using Microsoft.AspNetCore.Components.Forms;

#line default
#line hidden
#nullable disable
#nullable restore
#line 5 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using Microsoft.AspNetCore.Components.Routing;

#line default
#line hidden
#nullable disable
#nullable restore
#line 6 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using Microsoft.AspNetCore.Components.Web;

#line default
#line hidden
#nullable disable
#nullable restore
#line 7 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using Microsoft.AspNetCore.Components.Web.Virtualization;

#line default
#line hidden
#nullable disable
#nullable restore
#line 8 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using Microsoft.JSInterop;

#line default
#line hidden
#nullable disable
#nullable restore
#line 9 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using LDAP;

#line default
#line hidden
#nullable disable
#nullable restore
#line 10 "C:\Users\lhotchkiss\source\repos\LDAP\_Imports.razor"
using LDAP.Shared;

#line default
#line hidden
#nullable disable
#nullable restore
#line 4 "C:\Users\lhotchkiss\source\repos\LDAP\Pages\Login.razor"
           [AllowAnonymous]

#line default
#line hidden
#nullable disable
    [Microsoft.AspNetCore.Components.RouteAttribute("/login")]
    [Microsoft.AspNetCore.Components.RouteAttribute("/login/{ErrorMessage}")]
    public partial class Login : Microsoft.AspNetCore.Components.ComponentBase
    {
        #pragma warning disable 1998
        protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder __builder)
        {
            __builder.AddMarkupContent(0, "<h3>Login</h3>");
#nullable restore
#line 8 "C:\Users\lhotchkiss\source\repos\LDAP\Pages\Login.razor"
 if (ErrorMessage != null)
{

#line default
#line hidden
#nullable disable
            __builder.OpenElement(1, "div");
            __builder.AddAttribute(2, "class", "text-danger");
            __builder.AddContent(3, 
#nullable restore
#line 10 "C:\Users\lhotchkiss\source\repos\LDAP\Pages\Login.razor"
                              ErrorMessage

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
#nullable restore
#line 11 "C:\Users\lhotchkiss\source\repos\LDAP\Pages\Login.razor"
}

#line default
#line hidden
#nullable disable
            __builder.AddMarkupContent(4, @"<form method=""post"" action=""account/login""><div class=""form-group""><label>Username:</label>
        <input type=""text"" name=""username"" class=""form-control col-sm-6 col-md-4""></div>
    <div class=""form-group""><label>Password:</label>
        <input type=""password"" name=""password"" class=""form-control col-sm-6 col-md-4""></div>
    <button class=""btn btn-primary"">Log in</button></form>");
        }
        #pragma warning restore 1998
#nullable restore
#line 25 "C:\Users\lhotchkiss\source\repos\LDAP\Pages\Login.razor"
       
    [Parameter] public string ErrorMessage { get; set; }

#line default
#line hidden
#nullable disable
        [global::Microsoft.AspNetCore.Components.InjectAttribute] private NavigationManager NavManager { get; set; }
    }
}
#pragma warning restore 1591
