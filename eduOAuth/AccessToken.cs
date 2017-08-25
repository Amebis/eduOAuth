/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace eduOAuth
{
    /// <summary>
    /// Access token
    /// </summary>
    [Serializable]
    public class AccessToken : IDisposable, ISerializable
    {
        #region Fields

        private byte[] _entropy =
        {
            0x83, 0xb3, 0x15, 0xa2, 0x81, 0x57, 0x01, 0x0d, 0x8c, 0x21, 0x04, 0xd9, 0x11, 0xb3, 0xa7, 0x32,
            0xba, 0xb9, 0x8c, 0x15, 0x7b, 0x64, 0x32, 0x2b, 0x2f, 0x5f, 0x0e, 0x0d, 0xe5, 0x0a, 0x91, 0xc4,
            0x46, 0x81, 0xae, 0x72, 0xf6, 0xa7, 0x01, 0x67, 0x01, 0x91, 0x66, 0x1b, 0x5e, 0x5a, 0x51, 0xaa,
            0xbe, 0xf3, 0x23, 0x2a, 0x01, 0xc5, 0x8d, 0x01, 0x24, 0x56, 0x9b, 0xbd, 0xa6, 0xa3, 0x87, 0x87,
        };

        /// <summary>
        /// Access token
        /// </summary>
        protected SecureString token;

        /// <summary>
        /// Refresh token
        /// </summary>
        private SecureString refresh;

        #endregion

        #region Properties

        /// <summary>
        /// Access token expiration date; or <c>null</c> if token does not expire
        /// </summary>
        public DateTime? Expires { get; }

        /// <summary>
        /// List of access token scope identifiers
        /// </summary>
        public string[] Scope { get => _scope; }
        private string[] _scope;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes generic access token from data returned by authentication server.
        /// </summary>
        /// <param name="obj">An object representing access token as returned by the authentication server</param>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-5.1"/>
        protected AccessToken(Dictionary<string, object> obj)
        {
            // Get access token.
            token = (new NetworkCredential("", eduJSON.Parser.GetValue<string>(obj, "access_token"))).SecurePassword;
            token.MakeReadOnly();

            // Get expiration date.
            if (eduJSON.Parser.GetValue(obj, "expires_in", out int expires_in))
                Expires = DateTime.Now.AddSeconds(expires_in);

            // Get refresh token
            if (eduJSON.Parser.GetValue(obj, "refresh_token", out string refresh_token))
            {
                refresh = (new NetworkCredential("", refresh_token)).SecurePassword;
                refresh.MakeReadOnly();
            }

            // Get scope
            if (eduJSON.Parser.GetValue(obj, "scope", out string scope))
                _scope = scope.Split(null);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Adds token to request
        /// </summary>
        /// <param name="req">Web request</param>
        public virtual void AddToRequest(HttpWebRequest req)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Serializes access token to Base64 encoded string
        /// </summary>
        /// <returns>Serialized and Base64 encoded representation of access token</returns>
        public string ToBase64String()
        {
            using (var stream = new MemoryStream())
            {
                var formatter = new BinaryFormatter();
                formatter.Serialize(stream, this);
                return Convert.ToBase64String(stream.ToArray());
            }
        }

        /// <summary>
        /// Deserialize access token from Base64 encoded string
        /// </summary>
        /// <param name="base64">Serialized and Base64 encoded representation of access token</param>
        /// <returns>Access token</returns>
        public static AccessToken FromBase64String(string base64)
        {
            using (var stream = new MemoryStream(Convert.FromBase64String(base64)))
            {
                var formatter = new BinaryFormatter();
                return (AccessToken)formatter.Deserialize(stream);
            }
        }

        /// <summary>
        /// Parses authorization server response and creates an access token from it.
        /// </summary>
        /// <param name="req">Authorization server request</param>
        /// <param name="scope">Expected scope</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Asynchronous operation with expected access token</returns>
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "HttpWebResponse, Stream, and StreamReader tolerate multiple disposes.")]
        public static async Task<AccessToken> FromAuthorizationServerResponseAsync(HttpWebRequest req, string[] scope = null, CancellationToken ct = default(CancellationToken))
        {
            try
            {
                // Read and parse the response.
                using (var response = (HttpWebResponse)await req.GetResponseAsync())
                using (var stream_res = response.GetResponseStream())
                using (var reader = new StreamReader(stream_res))
                {
                    var obj = (Dictionary<string, object>)eduJSON.Parser.Parse(await reader.ReadToEndAsync(), ct);

                    // Get token type and create the token based on the type.
                    var token_type = eduJSON.Parser.GetValue<string>(obj, "token_type");
                    AccessToken token = null;
                    switch (token_type.ToLowerInvariant())
                    {
                        case "bearer": token = new BearerToken(obj); break;
                        default: throw new UnsupportedTokenTypeException(token_type);
                    }

                    if (token._scope == null && scope != null)
                    {
                        // The authorization server did not specify a token scope in response.
                        // The scope is assumed the same as have been requested.
                        token._scope = scope;
                    }

                    return token;
                }
            }
            catch (WebException ex)
            {
                var response = (HttpWebResponse)ex.Response;
                if (response.StatusCode == HttpStatusCode.BadRequest)
                {
                    // Parse server error.
                    using (var stream_res = response.GetResponseStream())
                    using (var reader = new StreamReader(stream_res))
                    {
                        var obj = (Dictionary<string, object>)eduJSON.Parser.Parse(await reader.ReadToEndAsync(), ct);
                        eduJSON.Parser.GetValue(obj, "error_description", out string error_description);
                        eduJSON.Parser.GetValue(obj, "error_uri", out string error_uri);
                        throw new AccessTokenException(eduJSON.Parser.GetValue<string>(obj, "error"), error_description, error_uri);
                    }
                }
                else
                    throw;
            }
        }

        /// <summary>
        /// Uses the refresh token to obtain a new access token. The new access token is requested using the same scope as initially granted to the access token.
        /// </summary>
        /// <param name="token_endpoint">URI of the token endpoint used to obtain access token from authorization grant</param>
        /// <param name="client_cred">Client credentials (optional)</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Access token</returns>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-6"/>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-5.1"/>
        public AccessToken RefreshToken(Uri token_endpoint, NetworkCredential client_cred = null, CancellationToken ct = default(CancellationToken))
        {
            var task = RefreshTokenAsync(token_endpoint, client_cred, ct);
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
        /// Uses the refresh token to obtain a new access token asynchronously. The new access token is requested using the same scope as initially granted to the access token.
        /// </summary>
        /// <param name="token_endpoint">URI of the token endpoint used to obtain access token from authorization grant</param>
        /// <param name="client_cred">Client credentials (optional)</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Asynchronous operation with expected access token</returns>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-6"/>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-5.1"/>
        public async Task<AccessToken> RefreshTokenAsync(Uri token_endpoint, NetworkCredential client_cred = null, CancellationToken ct = default(CancellationToken))
        {
            // Prepare token request body.
            // TODO: Verify confidentiality of Uri.EscapeDataString when handling security sensitive strings.
            string body =
                "grant_type=refresh_token" +
                "&refresh_token=" + Uri.EscapeDataString(new NetworkCredential("", refresh).Password);
            if (_scope != null)
                body += "&scope=" + Uri.EscapeDataString(String.Join(" ", _scope));

            // Send the request.
            var request = (HttpWebRequest)WebRequest.Create(token_endpoint);
            request.Method = "POST";
            if (client_cred != null)
            {
                // Our client has credentials: requires authentication.
                request.Credentials = new CredentialCache
                {
                    { token_endpoint, "Basic", client_cred }
                };
                request.PreAuthenticate = true;
            }
            var body_binary = Encoding.ASCII.GetBytes(body);
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = body_binary.Length;
            request.Accept = "application/json";
            using (var stream_req = await request.GetRequestStreamAsync())
            {
                // Send request body.
                await stream_req.WriteAsync(body_binary, 0, body_binary.Length, ct);

                // Parse the response.
                var token = await FromAuthorizationServerResponseAsync(request, _scope, ct);

                if (token.refresh == null)
                {
                    // The authorization server does not cycle the refresh tokens.
                    // The refresh token remains the same.
                    token.refresh = refresh;
                }

                return token;
            }
        }

        #endregion

        #region ISerializable Support

        protected AccessToken(SerializationInfo info, StreamingContext context)
        {
            // Load access token.
            // TODO: Verify confidentiality of Encoding.UTF8 when handling security sensitive strings.
            token =
                (new NetworkCredential("",
                    Encoding.UTF8.GetString(
                        ProtectedData.Unprotect(
                            (byte[])info.GetValue("Token", typeof(byte[])),
                            _entropy,
                            DataProtectionScope.CurrentUser)))).SecurePassword;
            token.MakeReadOnly();

            byte[] _refresh = null;
            try
            {
                _refresh = (byte[])info.GetValue("Refresh", typeof(byte[]));
            }
            catch (SerializationException) { }
            if (_refresh != null)
            {
                // Load refresh token.
                // TODO: Verify confidentiality of Encoding.UTF8 when handling security sensitive strings.
                refresh =
                    (new NetworkCredential("",
                        Encoding.UTF8.GetString(
                            ProtectedData.Unprotect(
                                _refresh,
                                _entropy,
                                DataProtectionScope.CurrentUser)))).SecurePassword;
                refresh.MakeReadOnly();
            }
            else
                refresh = null;

            // Load other fields and properties.
            Expires = (DateTime?)info.GetValue("Expires", typeof(DateTime?));
            _scope = (string[])info.GetValue("Scope", typeof(string[]));
        }

        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public virtual void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // Save access token.
            info.AddValue("Token",
                ProtectedData.Protect(
                    Encoding.UTF8.GetBytes(
                        new NetworkCredential("", token).Password),
                    _entropy,
                    DataProtectionScope.CurrentUser));

            if (refresh != null)
            {
                // Save refresh token.
                info.AddValue("Refresh",
                    ProtectedData.Protect(
                        Encoding.UTF8.GetBytes(
                            new NetworkCredential("", refresh).Password),
                        _entropy,
                        DataProtectionScope.CurrentUser));
            }

            // Save other fields and properties.
            info.AddValue("Expires", Expires);
            info.AddValue("Scope", _scope);
        }

        #endregion

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    token.Dispose();
                    refresh.Dispose();
                }

                disposedValue = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
