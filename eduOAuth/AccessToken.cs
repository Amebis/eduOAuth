﻿/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017-2020 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
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

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly byte[] _entropy =
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
        /// Access token expiration date; or <see cref="DateTime.MaxValue"/> if token does not expire
        /// </summary>
        public DateTime Expires { get; }

        /// <summary>
        /// List of access token scope identifiers
        /// </summary>
        public HashSet<string> Scope { get => _scope; }

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private HashSet<string> _scope;

        #endregion

        #region Constructors

        /// <summary>
        /// Initializes generic access token from data returned by authentication server.
        /// </summary>
        /// <param name="obj">An object representing access token as returned by the authentication server</param>
        /// <remarks>
        /// <a href="https://tools.ietf.org/html/rfc6749#section-5.1">RFC6749 Section 5.1</a>
        /// </remarks>
        protected AccessToken(Dictionary<string, object> obj)
        {
            // Get access token.
            _token = (new NetworkCredential("", eduJSON.Parser.GetValue<string>(obj, "access_token"))).SecurePassword;
            _token.MakeReadOnly();

            // Get expiration date.
            Expires = eduJSON.Parser.GetValue(obj, "expires_in", out int expires_in) ? DateTime.Now.AddSeconds(expires_in) : DateTime.MaxValue;

            // Get refresh token.
            if (eduJSON.Parser.GetValue(obj, "refresh_token", out string refresh_token))
            {
                _refresh = (new NetworkCredential("", refresh_token)).SecurePassword;
                _refresh.MakeReadOnly();
            }

            // Get scope.
            if (eduJSON.Parser.GetValue(obj, "scope", out string scope))
                _scope = new HashSet<string>(scope.Split(null));
        }

        #endregion

        #region Methods

        /// <inheritdoc/>
        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;
            if (obj == null || GetType() != obj.GetType())
                return false;

            var other = obj as AccessToken;
            if (!new NetworkCredential("", _token).Password.Equals(new NetworkCredential("", other._token).Password))
                return false;

            return true;
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return
                new NetworkCredential("", _token).Password.GetHashCode();
        }

        /// <summary>
        /// Adds token to request
        /// </summary>
        /// <param name="request">Web request</param>
        public virtual void AddToRequest(WebRequest request)
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
        /// <param name="request">Authorization server request</param>
        /// <param name="scope">Expected scope</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Access token</returns>
        public static AccessToken FromAuthorizationServerResponse(WebRequest request, HashSet<string> scope = null, CancellationToken ct = default(CancellationToken))
        {
            var task = FromAuthorizationServerResponseAsync(request, scope, ct);
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
        /// <param name="request">Authorization server request</param>
        /// <param name="scope">Expected scope</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Asynchronous operation with expected access token</returns>
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "WebResponse, Stream, and StreamReader tolerate multiple disposes.")]
        public static async Task<AccessToken> FromAuthorizationServerResponseAsync(WebRequest request, HashSet<string> scope = null, CancellationToken ct = default(CancellationToken))
        {
            try
            {
                // Read and parse the response.
                using (var response = await request.GetResponseAsync())
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
                if (ex.Response is HttpWebResponse response_http)
                {
                    if (response_http.StatusCode == HttpStatusCode.BadRequest)
                    {
                        // Parse server error.
                        using (var stream_res = response_http.GetResponseStream())
                        using (var reader = new StreamReader(stream_res))
                        {
                            var obj = (Dictionary<string, object>)eduJSON.Parser.Parse(await reader.ReadToEndAsync(), ct);
                            eduJSON.Parser.GetValue(obj, "error_description", out string error_description);
                            eduJSON.Parser.GetValue(obj, "error_uri", out string error_uri);
                            throw new AccessTokenException(eduJSON.Parser.GetValue<string>(obj, "error"), error_description, error_uri);
                        }
                    }

                    throw new WebExceptionEx(ex, ct);
                }

                throw;
            }
        }

        /// <summary>
        /// Uses the refresh token to obtain a new access token. The new access token is requested using the same scope as initially granted to the access token.
        /// </summary>
        /// <param name="request">Web request of the token endpoint used to obtain access token from authorization grant</param>
        /// <param name="client_cred">Client credentials (optional)</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Access token</returns>
        /// <remarks>
        /// <a href="https://tools.ietf.org/html/rfc6749#section-5.1">RFC6749 Section 5.1</a>,
        /// <a href="https://tools.ietf.org/html/rfc6749#section-6">RFC6749 Section 6</a>
        /// </remarks>
        public AccessToken RefreshToken(WebRequest request, NetworkCredential client_cred = null, CancellationToken ct = default(CancellationToken))
        {
            var task = RefreshTokenAsync(request, client_cred, ct);
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
        /// <param name="request">Web request of the token endpoint used to obtain access token from authorization grant</param>
        /// <param name="client_cred">Client credentials (optional)</param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        /// <returns>Asynchronous operation with expected access token</returns>
        /// <remarks>
        /// <a href="https://tools.ietf.org/html/rfc6749#section-5.1">RFC6749 Section 5.1</a>
        /// <a href="https://tools.ietf.org/html/rfc6749#section-6">RFC6749 Section 6</a>
        /// </remarks>
        public async Task<AccessToken> RefreshTokenAsync(WebRequest request, NetworkCredential client_cred = null, CancellationToken ct = default(CancellationToken))
        {
            // Prepare token request body.
            string body =
                "grant_type=refresh_token" +
                "&refresh_token=" + Uri.EscapeDataString(new NetworkCredential("", _refresh).Password);
            if (_scope != null)
                body += "&scope=" + Uri.EscapeDataString(String.Join(" ", _scope));

            // Send the request.
            request.Method = "POST";
            if (client_cred != null)
            {
                // Our client has credentials: requires authentication.
                request.Credentials = new CredentialCache
                {
                    { request.RequestUri, "Basic", client_cred }
                };
                request.PreAuthenticate = true;
            }
            var body_binary = Encoding.ASCII.GetBytes(body);
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = body_binary.Length;
            using (var stream_req = await request.GetRequestStreamAsync())
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
        /// Decrypts the data in a specified byte array and returns a <see cref="SecureString"/> that contains the decrypted data
        /// </summary>
        /// <param name="encryptedData">A byte array containing data encrypted using the <c>System.Security.Cryptography.ProtectedData.Protect(System.Byte[],System.Byte[],System.Security.Cryptography.DataProtectionScope)</c> method.</param>
        /// <returns>A <see cref="SecureString"/> representing the decrypted data</returns>
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

        /// <summary>
        /// Deserialize object.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> populated with data.</param>
        /// <param name="context">The source of this deserialization.</param>
        protected AccessToken(SerializationInfo info, StreamingContext context)
        {
            // Load access token.
            _token = Unprotect((byte[])info.GetValue("Token", typeof(byte[])));

            // Load refresh token.
            byte[] refresh = null;
            try { refresh = (byte[])info.GetValue("Refresh", typeof(byte[])); }
            catch (SerializationException) { }
            _refresh = refresh != null ? Unprotect(refresh) : null;

            // Load other fields and properties.
            Expires = (DateTime)info.GetValue("Expires", typeof(DateTime));

            string[] scope = null;
            try { scope = (string[])info.GetValue("Scope", typeof(string[])); }
            catch (SerializationException) { }
            _scope = scope != null ? new HashSet<string>(scope) : null;
        }

        /// <summary>
        /// Populates a <see cref="SerializationInfo"/> with the data needed to serialize the target object.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> to populate with data.</param>
        /// <param name="context">The destination for this serialization.</param>
        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public virtual void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            // Save access token.
            info.AddValue("Token", Protect(_token));

            // Save refresh token.
            if (_refresh != null)
                info.AddValue("Refresh", Protect(_refresh));

            // Save other fields and properties.
            info.AddValue("Expires", Expires);
            if (_scope != null)
                info.AddValue("Scope", _scope.ToArray());
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
                    if (_token != null)
                        _token.Dispose();

                    if (_refresh != null)
                        _refresh.Dispose();
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
