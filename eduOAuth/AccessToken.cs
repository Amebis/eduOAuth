/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
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

        private static byte[] _entropy =
        {
            0x83, 0xb3, 0x15, 0xa2, 0x81, 0x57, 0x01, 0x0d, 0x8c, 0x21, 0x04, 0xd9, 0x11, 0xb3, 0xa7, 0x32,
            0xba, 0xb9, 0x8c, 0x15, 0x7b, 0x64, 0x32, 0x2b, 0x2f, 0x5f, 0x0e, 0x0d, 0xe5, 0x0a, 0x91, 0xc4,
            0x46, 0x81, 0xae, 0x72, 0xf6, 0xa7, 0x01, 0x67, 0x01, 0x91, 0x66, 0x1b, 0x5e, 0x5a, 0x51, 0xaa,
            0xbe, 0xf3, 0x23, 0x2a, 0x01, 0xc5, 0x8d, 0x01, 0x24, 0x56, 0x9b, 0xbd, 0xa6, 0xa3, 0x87, 0x87,
        };

        /// <summary>
        /// Access token
        /// </summary>
        protected SecureString _token;

        /// <summary>
        /// Refresh token
        /// </summary>
        private SecureString _refresh;

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
            _token = (new NetworkCredential("", eduJSON.Parser.GetValue<string>(obj, "access_token"))).SecurePassword;
            _token.MakeReadOnly();

            // Get expiration date.
            if (eduJSON.Parser.GetValue(obj, "expires_in", out int expires_in))
                Expires = DateTime.Now.AddSeconds(expires_in);

            // Get refresh token
            if (eduJSON.Parser.GetValue(obj, "refresh_token", out string refresh_token))
            {
                _refresh = (new NetworkCredential("", refresh_token)).SecurePassword;
                _refresh.MakeReadOnly();
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
        public virtual void AddToRequest(WebRequest req)
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
        /// <returns>Access token</returns>
        public static AccessToken FromAuthorizationServerResponse(HttpWebRequest req, string[] scope = null, CancellationToken ct = default(CancellationToken))
        {
            var task = FromAuthorizationServerResponseAsync(req, scope, ct);
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
        /// Parses authorization server response and creates an access token from it asynchronously.
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
            string body =
                "grant_type=refresh_token" +
                "&refresh_token=" + Uri.EscapeDataString(new NetworkCredential("", _refresh).Password);
            if (_scope != null)
                body += "&scope=" + Uri.EscapeDataString(String.Join(" ", _scope));

            // Send the request.
            var request = (HttpWebRequest)WebRequest.Create(token_endpoint);
            var assembly = Assembly.GetExecutingAssembly();
            var assembly_title_attribute = Attribute.GetCustomAttributes(assembly, typeof(AssemblyTitleAttribute)).SingleOrDefault() as AssemblyTitleAttribute;
            var assembly_version = assembly?.GetName()?.Version;
            request.UserAgent = assembly_title_attribute?.Title + "/" + assembly_version?.ToString();
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

                if (token._refresh == null)
                {
                    // The authorization server does not cycle the refresh tokens.
                    // The refresh token remains the same.
                    token._refresh = _refresh;
                }

                return token;
            }
        }

        /// <summary>
        /// Encrypts the data in a specified secure string and returns a byte array that contains the encrypted data
        /// </summary>
        /// <param name="userData">A secure string that contains data to encrypt</param>
        /// <returns>A byte array representing the encrypted data</returns>
        private static byte[] Protect(SecureString userData)
        {
            if (userData == null)
                throw new ArgumentNullException(nameof(userData));

            // Copy input to unmanaged string.
            IntPtr input_exposed = Marshal.SecureStringToGlobalAllocUnicode(userData);
            try
            {
                var data = new byte[userData.Length * sizeof(char)];
                try
                {
                    // Copy data.
                    for (int i = 0, n = data.Length; i < n; i++)
                        data[i] = Marshal.ReadByte(input_exposed, i);

                    // Encrypt!
                    return ProtectedData.Protect(
                        data,
                        _entropy,
                        DataProtectionScope.CurrentUser);
                }
                finally
                {
                    // Sanitize data.
                    for (long i = 0, n = data.LongLength; i < n; i++)
                        data[i] = 0;
                }
            }
            finally
            {
                // Sanitize memory.
                Marshal.ZeroFreeGlobalAllocUnicode(input_exposed);
            }
        }

        /// <summary>
        /// Decrypts the data in a specified byte array and returns a <c>SecureString</c> that contains the decrypted data
        /// </summary>
        /// <param name="encryptedData">A byte array containing data encrypted using the <c>System.Security.Cryptography.ProtectedData.Protect(System.Byte[],System.Byte[],System.Security.Cryptography.DataProtectionScope)</c> method.</param>
        /// <returns>A <c>SafeString</c> representing the decrypted data</returns>
        private static SecureString Unprotect(byte[] encryptedData)
        {
            // Decrypt data.
            var data = ProtectedData.Unprotect(encryptedData, _entropy, DataProtectionScope.CurrentUser);
            try
            {
                // Copy to SecureString.
                var output = new SecureString();
                for (long i = 0, n = data.LongLength; i < n; i += 2)
                    output.AppendChar((char)(data[i] + (((char)data[i + 1]) << 8)));
                output.MakeReadOnly();
                return output;
            }
            finally
            {
                // Sanitize data.
                for (long i = 0, n = data.LongLength; i < n; i++)
                    data[i] = 0;
            }
        }

        #endregion

        #region ISerializable Support

        protected AccessToken(SerializationInfo info, StreamingContext context)
        {
            // Load access token.
            _token = Unprotect((byte[])info.GetValue("Token", typeof(byte[])));

            byte[] refresh = null;
            try
            {
                refresh = (byte[])info.GetValue("Refresh", typeof(byte[]));
            }
            catch (SerializationException) { }
            if (refresh != null)
            {
                // Load refresh token.
                _refresh = Unprotect(refresh);
            }
            else
                _refresh = null;

            // Load other fields and properties.
            Expires = (DateTime?)info.GetValue("Expires", typeof(DateTime?));
            _scope = (string[])info.GetValue("Scope", typeof(string[]));
        }

        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public virtual void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // Save access token.
            info.AddValue("Token", Protect(_token));

            if (_refresh != null)
            {
                // Save refresh token.
                info.AddValue("Refresh", Protect(_refresh));
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
                    if (_token != null)
                        _token.Dispose();

                    if (_refresh != null)
                        _refresh.Dispose();
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
