﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace eduOAuth.Resources {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "15.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class Strings {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Strings() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("eduOAuth.Resources.Strings", typeof(Strings).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)..
        /// </summary>
        internal static string ErrorAccessTokenInvalidClient {
            get {
                return ResourceManager.GetString("ErrorAccessTokenInvalidClient", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client..
        /// </summary>
        internal static string ErrorAccessTokenInvalidGrant {
            get {
                return ResourceManager.GetString("ErrorAccessTokenInvalidGrant", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed..
        /// </summary>
        internal static string ErrorAccessTokenInvalidRequest {
            get {
                return ResourceManager.GetString("ErrorAccessTokenInvalidRequest", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner..
        /// </summary>
        internal static string ErrorAccessTokenInvalidScope {
            get {
                return ResourceManager.GetString("ErrorAccessTokenInvalidScope", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The authenticated client is not authorized to use this authorization grant type..
        /// </summary>
        internal static string ErrorAccessTokenUnauthorizedClient {
            get {
                return ResourceManager.GetString("ErrorAccessTokenUnauthorizedClient", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The authorization grant type is not supported by the authorization server..
        /// </summary>
        internal static string ErrorAccessTokenUnsupportedGrantType {
            get {
                return ResourceManager.GetString("ErrorAccessTokenUnsupportedGrantType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The resource owner or authorization server denied the request..
        /// </summary>
        internal static string ErrorAuthorizationGrantAccessDenied {
            get {
                return ResourceManager.GetString("ErrorAuthorizationGrantAccessDenied", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed..
        /// </summary>
        internal static string ErrorAuthorizationGrantInvalidRequest {
            get {
                return ResourceManager.GetString("ErrorAuthorizationGrantInvalidRequest", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The requested scope is invalid, unknown, or malformed..
        /// </summary>
        internal static string ErrorAuthorizationGrantInvalidScope {
            get {
                return ResourceManager.GetString("ErrorAuthorizationGrantInvalidScope", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The authorization server encountered an unexpected condition that prevented it from fulfilling the request..
        /// </summary>
        internal static string ErrorAuthorizationGrantServerError {
            get {
                return ResourceManager.GetString("ErrorAuthorizationGrantServerError", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server..
        /// </summary>
        internal static string ErrorAuthorizationGrantTemporarilyUnavailable {
            get {
                return ResourceManager.GetString("ErrorAuthorizationGrantTemporarilyUnavailable", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The client is not authorized to request an authorization code using this method..
        /// </summary>
        internal static string ErrorAuthorizationGrantUnauthorizedClient {
            get {
                return ResourceManager.GetString("ErrorAuthorizationGrantUnauthorizedClient", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The authorization server does not support obtaining an authorization code using this method..
        /// </summary>
        internal static string ErrorAuthorizationGrantUnsupportedResponseType {
            get {
                return ResourceManager.GetString("ErrorAuthorizationGrantUnsupportedResponseType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Invalid HTTP request: {0}.
        /// </summary>
        internal static string ErrorHttp400 {
            get {
                return ResourceManager.GetString("ErrorHttp400", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Path {0} not found..
        /// </summary>
        internal static string ErrorHttp404 {
            get {
                return ResourceManager.GetString("ErrorHttp404", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Method {0} not supported..
        /// </summary>
        internal static string ErrorHttp405 {
            get {
                return ResourceManager.GetString("ErrorHttp405", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Response and request states are different..
        /// </summary>
        internal static string ErrorInvalidState {
            get {
                return ResourceManager.GetString("ErrorInvalidState", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to {0} (token type: {1}).
        /// </summary>
        internal static string ErrorTokenType {
            get {
                return ResourceManager.GetString("ErrorTokenType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The received token type is not supported..
        /// </summary>
        internal static string ErrorUnsupportedTokenType {
            get {
                return ResourceManager.GetString("ErrorUnsupportedTokenType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Please try again later or contact your helpdesk for support..
        /// </summary>
        internal static string HtmlErrorDescription {
            get {
                return ResourceManager.GetString("HtmlErrorDescription", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Details....
        /// </summary>
        internal static string HtmlErrorDetails {
            get {
                return ResourceManager.GetString("HtmlErrorDetails", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Error.
        /// </summary>
        internal static string HtmlErrorTitle {
            get {
                return ResourceManager.GetString("HtmlErrorTitle", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to You can now close this tab..
        /// </summary>
        internal static string HtmlFinishedDescription {
            get {
                return ResourceManager.GetString("HtmlFinishedDescription", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The client succesfully authorized..
        /// </summary>
        internal static string HtmlFinishedTitle {
            get {
                return ResourceManager.GetString("HtmlFinishedTitle", resourceCulture);
            }
        }
    }
}
