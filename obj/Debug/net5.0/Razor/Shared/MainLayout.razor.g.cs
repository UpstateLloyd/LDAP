#pragma checksum "C:\Users\lhotchkiss\source\repos\LDAP\Shared\MainLayout.razor" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "7b99061c831f9c4781ee5193a3f251e785d90684"
// <auto-generated/>
#pragma warning disable 1591
namespace LDAP.Shared
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
    public partial class MainLayout : LayoutComponentBase
    {
        #pragma warning disable 1998
        protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder __builder)
        {
            __builder.OpenElement(0, "div");
            __builder.AddAttribute(1, "class", "page");
            __builder.AddAttribute(2, "b-bbglcj825e");
            __builder.OpenElement(3, "div");
            __builder.AddAttribute(4, "class", "sidebar");
            __builder.AddAttribute(5, "b-bbglcj825e");
            __builder.OpenComponent<LDAP.Shared.NavMenu>(6);
            __builder.CloseComponent();
            __builder.CloseElement();
            __builder.AddMarkupContent(7, "\r\n\r\n    ");
            __builder.OpenElement(8, "div");
            __builder.AddAttribute(9, "class", "main");
            __builder.AddAttribute(10, "b-bbglcj825e");
            __builder.OpenElement(11, "div");
            __builder.AddAttribute(12, "class", "top-row px-4");
            __builder.AddAttribute(13, "b-bbglcj825e");
            __builder.AddMarkupContent(14, "<h3 b-bbglcj825e>Authorized View</h3>\r\n            ");
            __builder.OpenComponent<Microsoft.AspNetCore.Components.Authorization.AuthorizeView>(15);
            __builder.AddAttribute(16, "Authorized", (Microsoft.AspNetCore.Components.RenderFragment<Microsoft.AspNetCore.Components.Authorization.AuthenticationState>)((context) => (__builder2) => {
                __builder2.OpenElement(17, "span");
                __builder2.AddAttribute(18, "class", "ml-md-auto");
                __builder2.AddAttribute(19, "b-bbglcj825e");
                __builder2.AddMarkupContent(20, "\r\n                        User Connected: ");
                __builder2.AddContent(21, 
#nullable restore
#line 14 "C:\Users\lhotchkiss\source\repos\LDAP\Shared\MainLayout.razor"
                                         context.User.Identity.Name

#line default
#line hidden
#nullable disable
                );
                __builder2.AddMarkupContent(22, "\r\n                        ");
                __builder2.AddMarkupContent(23, "<a href=\"/account/logout\" b-bbglcj825e>Logout</a>");
                __builder2.CloseElement();
            }
            ));
            __builder.AddAttribute(24, "NotAuthorized", (Microsoft.AspNetCore.Components.RenderFragment<Microsoft.AspNetCore.Components.Authorization.AuthenticationState>)((context) => (__builder2) => {
                __builder2.AddMarkupContent(25, "<a href=\"login\" class=\"ml-md-auto\" b-bbglcj825e>Login</a>");
            }
            ));
            __builder.CloseComponent();
            __builder.CloseElement();
            __builder.AddMarkupContent(26, "\r\n\r\n        ");
            __builder.OpenElement(27, "div");
            __builder.AddAttribute(28, "class", "content px-4");
            __builder.AddAttribute(29, "b-bbglcj825e");
            __builder.AddContent(30, 
#nullable restore
#line 25 "C:\Users\lhotchkiss\source\repos\LDAP\Shared\MainLayout.razor"
             Body

#line default
#line hidden
#nullable disable
            );
            __builder.CloseElement();
            __builder.CloseElement();
            __builder.CloseElement();
        }
        #pragma warning restore 1998
    }
}
#pragma warning restore 1591