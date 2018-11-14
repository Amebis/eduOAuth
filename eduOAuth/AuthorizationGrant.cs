﻿/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017-2018 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace eduOAuth
{
    /// <summary>
    /// OAuth authorization grant
    /// </summary>
    public class AuthorizationGrant : IDisposable
    {
        #region Data Types

        /// <summary>
        /// Code challenge algorithm method types
        /// </summary>
        /// <remarks>
        /// <a href="https://tools.ietf.org/html/rfc7636#section-4.2">RFC7636 Section 4.2</a>
        /// </remarks>
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

        #endregion

        #region Fields

        /// <summary>
        /// PKCE code verifier
        /// </summary>
        private SecureString _code_verifier;

        #endregion

        #region Properties

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
        /// Code challenge algorithm method
        /// </summary>
        /// <remarks>
        /// <a href="https://tools.ietf.org/html/rfc7636#section-4.2">RFC7636 Section 4.2</a>
        /// </remarks>
        public CodeChallengeAlgorithmType CodeChallengeAlgorithm { get; set; }

        /// <summary>
        /// List of scope identifiers client is requesting access
        /// </summary>
        /// <remarks>Should be populated before requesting authorization. When empty, <c>scope</c> parameter is not included in authorization request URI.</remarks>
        public HashSet<string> Scope { get; set; }

        /// <summary>
        /// Random client state
        /// </summary>
        public SecureString State { get => _state; }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private SecureString _state;

        /// <summary>
        /// Authorization URI
        /// </summary>
        /// <remarks>
        /// <a href="https://tools.ietf.org/html/rfc6749#section-4.1.1">RFC6749 Section 4.1.1</a>,
        /// <a href="https://tools.ietf.org/html/rfc7636#section-4.1">RFC7636 Section 4.1</a>,
        /// <a href="https://tools.ietf.org/html/rfc7636#section-4.2">RFC7636 Section 4.2</a>,
        /// <a href="https://tools.ietf.org/html/rfc7636#section-4.3">RFC7636 Section 4.3</a>
        /// </remarks>
        public Uri AuthorizationURI
        {
            get
            {
                // Prepare authorization endpoint URI.
                var uri_builder = new UriBuilder(AuthorizationEndpoint);
                var query = HttpUtility.ParseQueryString(uri_builder.Query);

                query["response_type"] = "code";
                query["client_id"] = ClientID;
                query["redirect_uri"] = RedirectEndpoint.ToString();

                if (Scope != null)
                {
                    // Add the client requested scope.
                    query["scope"] = String.Join(" ", Scope.ToArray());
                }

                // Add the random state.
                query["state"] = new NetworkCredential("", _state).Password;

                if (CodeChallengeAlgorithm != CodeChallengeAlgorithmType.None)
                {
                    // Add the code challenge (RFC 7636).
                    switch (CodeChallengeAlgorithm)
                    {
                        case CodeChallengeAlgorithmType.Plain:
                            query["code_challenge_method"] = "plain";
                            query["code_challenge"] = new NetworkCredential("", _code_verifier).Password;
                            break;

                        case CodeChallengeAlgorithmType.S256:
                            query["code_challenge_method"] = "S256";

                            {
                                var sha256 = new SHA256Managed();
                                query["code_challenge"] = Base64URLEncodeNoPadding(sha256.ComputeHash(Encoding.ASCII.GetBytes(new NetworkCredential("", _code_verifier).Password)));
                            }
                            break;
                    }
                }

                uri_builder.Query = query.ToString();
                return uri_builder.Uri;
            }
        }

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes an authorization grant.
        /// </summary>
        public AuthorizationGrant() :
            this(new byte[0])
        {
        }

        /// <summary>
        /// Initializes an authorization grant.
        /// </summary>
        /// <param name="state_prefix">Data to prefix OAuth state with to allow disambiguation between multiple concurrent authorization requests</param>
        public AuthorizationGrant(byte[] state_prefix)
        {
            CodeChallengeAlgorithm = CodeChallengeAlgorithmType.S256;

            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            var random = new byte[32];
            try
            {
                // Calculate random state.
                rng.GetBytes(random);
                var state = new byte[state_prefix.LongLength + random.LongLength];
                try
                {
                    Array.Copy(state_prefix, 0, state, 0, state_prefix.LongLength);
                    Array.Copy(random, 0, state, state_prefix.LongLength, random.LongLength);
                    _state = new NetworkCredential("", Base64URLEncodeNoPadding(state)).SecurePassword;
                    _state.MakeReadOnly();
                }
                finally
                {
                    // Sanitize!
                    for (long i = 0, n = state.LongLength; i < n; i++)
                        state[i] = 0;
                }

                // Calculate code verifier.
                rng.GetBytes(random);
                _code_verifier = new NetworkCredential("", Base64URLEncodeNoPadding(random)).SecurePassword;
                _code_verifier.MakeReadOnly();
            }
            finally
            {
                // Sanitize!
                for (long i = 0, n = random.LongLength; i < n; i++)
                    random[i] = 0;
            }
        }

        #endregion

        #region Methods

        /// <summary>
        /// Parses authorization grant received and requests access token if successful.
        /// </summary>
        /// <param name="redirect_response">Parameters of the access grant</param>
        /// <param name="request">Web request of the token endpoint used to obtain access token from authorization grant</param>
        /// <param name="client_secret">Client secret (optional)</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Access token</returns>
        /// <remarks>
        /// <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC6749 Section 5.2</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2">RFC6749 Section 4.1.2</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2.1">RFC6749 Section 4.1.2.1</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3">RFC6749 Section 4.1.3</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-4.1.4">RFC6749 Section 4.1.4</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC6749 Section 5.2</a>,
        /// <a href="https://tools.ietf.org/html/rfc7636#section-4.5">RFC7636 Section 4.5</a>
        /// </remarks>
        public AccessToken ProcessResponse(NameValueCollection redirect_response, WebRequest request, SecureString client_secret = null, CancellationToken ct = default(CancellationToken))
        {
            var task = ProcessResponseAsync(redirect_response, request, client_secret, ct);
            try
            {
                task.Wait(ct);
                return task.Result;
            }
            catch (AggregateException ex)
            {
                throw ex.InnerException;
            }
        }

        /// <summary>
        /// Parses authorization grant received and requests access token if successful asynchronously.
        /// </summary>
        /// <param name="redirect_response">Parameters of the access grant</param>
        /// <param name="request">Web request of the token endpoint used to obtain access token from authorization grant</param>
        /// <param name="client_secret">Client secret (optional)</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Asynchronous operation with expected access token</returns>
        /// <remarks>
        /// <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC6749 Section 5.2</a>
        /// <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2">RFC6749 Section 4.1.2</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-4.1.2.1">RFC6749 Section 4.1.2.1</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3">RFC6749 Section 4.1.3</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-4.1.4">RFC6749 Section 4.1.4</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-5.2">RFC6749 Section 5.2</a>,
        /// <a href="https://tools.ietf.org/html/rfc7636#section-4.5">RFC7636 Section 4.5</a>
        /// </remarks>
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "HttpWebResponse, Stream, and StreamReader tolerate multiple disposes.")]
        public async Task<AccessToken> ProcessResponseAsync(NameValueCollection redirect_response, WebRequest request, SecureString client_secret = null, CancellationToken ct = default(CancellationToken))
        {
            // Verify state parameter to be present and matching.
            var response_state = redirect_response["state"];
            if (response_state == null)
                throw new eduJSON.MissingParameterException("state");
            if (!new NetworkCredential("", response_state).SecurePassword.IsEqualTo(_state))
                throw new InvalidStateException();

            // Did authorization server report an error?
            var response_error = redirect_response["error"];
            if (response_error != null)
                throw new AuthorizationGrantException(response_error, redirect_response["error_description"], redirect_response["error_uri"]);

            // Verify authorization code to be present.
            var authorization_code = redirect_response["code"]/*.Replace(' ', '+') <= IE11 sends URI unescaped causing + to get converted into space. The issue is avoided by switching to Base64URLEncodeNoPadding encoding.*/;
            if (authorization_code == null)
                throw new eduJSON.MissingParameterException("code");

            // Prepare token request body.
            string body =
                "grant_type=authorization_code" +
                "&code=" + Uri.EscapeDataString(authorization_code) +
                "&redirect_uri=" + Uri.EscapeDataString(RedirectEndpoint.ToString()) +
                "&client_id=" + Uri.EscapeDataString(ClientID);
            if (_code_verifier != null)
                body += "&code_verifier=" + new NetworkCredential("", _code_verifier).Password;

            // Send the request.
            request.Method = "POST";
            if (client_secret != null)
            {
                // Our client has credentials: requires authentication.
                request.Credentials = new CredentialCache
                {
                    { request.RequestUri, "Basic", new NetworkCredential(ClientID, client_secret) }
                };
                request.PreAuthenticate = true;
            }
            var body_binary = Encoding.ASCII.GetBytes(body);
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = body_binary.Length;
            using (var stream_req = await request.GetRequestStreamAsync())
                await stream_req.WriteAsync(body_binary, 0, body_binary.Length, ct);

            // Parse the response.
            return await AccessToken.FromAuthorizationServerResponseAsync(request, Scope, ct);
        }

        /// <summary>
        /// Encodes binary data for RFC 7636 request.
        /// </summary>
        /// <param name="data">Data to encode</param>
        /// <returns>Encoded string</returns>
        /// <remarks>
        /// <a href="https://tools.ietf.org/html/rfc7636#appendix-A">RFC7636 Appendix A</a>
        /// </remarks>
        public static string Base64URLEncodeNoPadding(byte[] data)
        {
            var s = Convert.ToBase64String(data); // Regular Base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        /// <summary>
        /// Decodes string for RFC 7636 request.
        /// </summary>
        /// <param name="data">String to decode</param>
        /// <returns>Decoded data</returns>
        public static byte[] Base64URLDecodeNoPadding(string data)
        {
            var s = data.Replace('_', '/'); // 63rd char of encoding
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.PadRight(s.Length + ((4 - s.Length) & 0x3), '='); // Add trailing '='s
            return Convert.FromBase64String(s); // Regular Base64 decoder
        }

        #endregion

        #region IDisposable Support
        /// <summary>
        /// Flag to detect redundant <see cref="Dispose(bool)"/> calls.
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private bool disposedValue = false;

        /// <summary>
        /// Called to dispose the object.
        /// </summary>
        /// <param name="disposing">Dispose managed objects</param>
        /// <remarks>
        /// To release resources for inherited classes, override this method.
        /// Call <c>base.Dispose(disposing)</c> within it to release parent class resources, and release child class resources if <paramref name="disposing"/> parameter is <c>true</c>.
        /// This method can get called multiple times for the same object instance. When the child specific resources should be released only once, introduce a flag to detect redundant calls.
        /// </remarks>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (_state != null)
                        _state.Dispose();

                    if (_code_verifier != null)
                        _code_verifier.Dispose();
                }

                disposedValue = true;
            }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting resources.
        /// </summary>
        /// <remarks>
        /// This method calls <see cref="Dispose(bool)"/> with <c>disposing</c> parameter set to <c>true</c>.
        /// To implement resource releasing override the <see cref="Dispose(bool)"/> method.
        /// </remarks>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
