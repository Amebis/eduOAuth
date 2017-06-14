/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net;
using System.Security;
//using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace eduOAuth
{
    class AuthorizationGrant
    {
        /// <summary>
        /// Initializes default authorization grant.
        /// </summary>
        public AuthorizationGrant()
        {
            CodeChallengeAlgorithm = CodeChallengeAlgorithmType.S256;

            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            var random = new byte[32];

            // Calculate random state.
            rng.GetBytes(random);
            state = Base64URLEncodeNoPadding(random);

            // Calculate code verifier.
            rng.GetBytes(random);
            code_verifier = Base64URLEncodeNoPadding(random);
        }

        /// <summary>
        /// Parses authorization grant received and requests access token if successful.
        /// </summary>
        /// <param name="redirect_response">Parameters of the access grant</param>
        /// <param name="token_endpoint">URI of the token endpoint used to obtain access token from authorization grant</param>
        /// <returns></returns>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-4.1.2"/>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-4.1.2.1"/>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-4.1.3"/>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-4.1.4"/>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-5.2"/>
        /// <see cref="https://tools.ietf.org/html/rfc7636#section-4.5"/>
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times")]
        public AccessToken ProcessResponse(NameValueCollection redirect_response, Uri token_endpoint)
        {
            // Verify state parameter to be present and matching.
            var response_state = redirect_response["state"];
            if (response_state == null)
                throw new eduJSON.MissingParameterException("state");
            if (response_state != state)
                throw new InvalidStateException();

            // Did authorization server report an error?
            var response_error = redirect_response["error"];
            if (response_error != null)
                throw new AuthorizationGrantException(response_error, redirect_response["error_description"], redirect_response["error_uri"]);

            // Verify authorization code to be present.
            var authorization_code = redirect_response["code"];
            if (authorization_code == null)
                throw new eduJSON.MissingParameterException("code");

            // Prepare token request body.
            string body =
                "grant_type=authorization_code" +
                "&code=" + Uri.EscapeDataString(authorization_code) +
                "&redirect_uri=" + Uri.EscapeDataString(RedirectEndpoint.ToString()) +
                "&client_id=" + Uri.EscapeDataString(ClientID);
            if (code_verifier != null)
                body += "&code_verifier=" + code_verifier;

            // Send the request.
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(token_endpoint);
            request.Method = "POST";
            if (ClientSecret != null)
            {
                // Our client has credentials: requires authentication.
                CredentialCache credential_cache = new CredentialCache();
                credential_cache.Add(token_endpoint, "Basic", new NetworkCredential(ClientID, ClientSecret));
                request.Credentials = credential_cache;
                request.PreAuthenticate = true;
            }
            byte[] body_binary = Encoding.ASCII.GetBytes(body);
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = body_binary.Length;
            using (Stream stream = request.GetRequestStream())
                stream.Write(body_binary, 0, body_binary.Length);

            try
            {
                // Read and parse the response.
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream))
                    return AccessToken.Create((Dictionary<string, object>)eduJSON.Parser.Parse(reader.ReadToEnd()));
            }
            catch (WebException ex)
            {
                if (((HttpWebResponse)ex.Response).StatusCode == HttpStatusCode.BadRequest)
                {
                    // Parse server error.
                    var response = (HttpWebResponse)ex.Response;
                    using (Stream stream = response.GetResponseStream())
                    using (StreamReader reader = new StreamReader(stream))
                        throw AccessTokenException.Create((Dictionary<string, object>)eduJSON.Parser.Parse(reader.ReadToEnd()));
                }
                else
                    throw;
            }
        }

        /// <summary>
        /// Encodes binary data for RFC 7636 request.
        /// </summary>
        /// <param name="data">Data to encode</param>
        /// <returns></returns>
        /// <see cref="https://tools.ietf.org/html/rfc7636#appendix-A"/>
        public static string Base64URLEncodeNoPadding(byte[] data)
        {
            string s = Convert.ToBase64String(data); // Regular Base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        //// ref http://stackoverflow.com/a/3978040
        //protected static int GetRandomUnusedPort()
        //{
        //    var listener = new TcpListener(IPAddress.Loopback, 0);
        //    listener.Start();
        //    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        //    listener.Stop();
        //    return port;
        //}

        /// <summary>
        /// Authorization endpoint base URI
        /// </summary>
        public Uri AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Redirection endpoint base URI
        /// </summary>
        /// <remarks>Client should setup a listener on this URI prior this method is called.</remarks>
        public Uri RedirectEndpoint { get; set; }

        /// <summary>
        /// Client ID
        /// </summary>
        /// <remarks>Should be populated before requesting authorization.</remarks>
        public string ClientID { get; set; }

        /// <summary>
        /// Client secret or <c>null</c> if client is not issued credentials.
        /// </summary>
        public SecureString ClientSecret { get; set; }

        /// <summary>
        /// Code challenge algorithm method types
        /// </summary>
        /// <see cref="https://tools.ietf.org/html/rfc7636#section-4.2"/>
        public enum CodeChallengeAlgorithmType
        {
            /// <summary>
            /// PKCE disabled
            /// </summary>
            None,

            /// <summary>
            /// Code challenge = Code verifier
            /// </summary>
            Plain,

            /// <summary>
            /// Code challenge = Base64URLEncodeNoPadding(SHA256(ASCII(Code verifier)))
            /// </summary>
            S256,
        }

        /// <summary>
        /// Code challenge algorithm method
        /// </summary>
        /// <see cref="https://tools.ietf.org/html/rfc7636#section-4.2"/>
        public CodeChallengeAlgorithmType CodeChallengeAlgorithm { get; set; }

        /// <summary>
        /// List of scope identifiers client is requesting access
        /// </summary>
        /// <remarks>Should be populated before requesting authorization. When empty <c>scope</c> parameter is not included in authorization request URI.</remarks>
        public List<string> Scope { get; set; }

        /// <summary>
        /// Authorization URI
        /// </summary>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-4.1.1"/>
        /// <see cref="https://tools.ietf.org/html/rfc7636#section-4.1"/>
        /// <see cref="https://tools.ietf.org/html/rfc7636#section-4.2"/>
        /// <see cref="https://tools.ietf.org/html/rfc7636#section-4.3"/>
        public Uri AuthorizationURI
        {
            get
            {
                //// Create a redirect URI using an available port on the loopback address.
                //var redirect_uri = "http://" + IPAddress.Loopback + ":" + GetRandomUnusedPort()  + "/callback";

                //// Start a HttpListener call-back (ASAP, while the TCP port is still free).
                //http = new HttpListener();
                //http.Prefixes.Add(redirect_uri);
                //http.Start();

                // Prepare authorization endpoint URI.
                var auth_uri_builder = new UriBuilder(AuthorizationEndpoint);
                auth_uri_builder.Query +=
                    (auth_uri_builder.Query.Length > 0 ? "&" : "?") + "response_type=code" +
                    "&client_id=" + Uri.EscapeDataString(ClientID) +
                    "&redirect_uri=" + Uri.EscapeDataString(RedirectEndpoint.ToString());

                if (Scope.Count > 0)
                {
                    // Add the client requested scope.
                    auth_uri_builder.Query += "&scope=" + Uri.EscapeDataString(String.Join(" ", Scope.ToArray()));
                }

                // Add the random state.
                auth_uri_builder.Query += "&state=" + state;

                if (CodeChallengeAlgorithm != CodeChallengeAlgorithmType.None)
                {
                    // Add the code challenge (RFC 7636).
                    switch (CodeChallengeAlgorithm)
                    {
                        case CodeChallengeAlgorithmType.Plain:
                            auth_uri_builder.Query += "&code_challenge_method=plain&code_challenge=" + code_verifier;
                            break;

                        case CodeChallengeAlgorithmType.S256:
                            {
                                var sha256 = new SHA256Managed();
                                auth_uri_builder.Query += "&code_challenge_method=S256&code_challenge=" + Base64URLEncodeNoPadding(sha256.ComputeHash(Encoding.ASCII.GetBytes(code_verifier)));
                            }
                            break;
                    }
                }
                else
                    code_verifier = null;

                //// Opens request in the browser.
                //System.Diagnostics.Process.Start(auth_uri_builder.Uri.ToString());

                return auth_uri_builder.Uri;
            }
        }

        /// <summary>
        /// Random client state
        /// </summary>
        private string state;

        /// <summary>
        /// PKCE code verifier
        /// </summary>
        private string code_verifier;

        ///// <summary>
        ///// HTTP server waiting for a call-back
        ///// </summary>
        //private HttpListener http;
    }
}
