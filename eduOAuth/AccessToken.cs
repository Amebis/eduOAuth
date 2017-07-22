/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;

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
        protected SecureString refresh;

        #endregion

        #region Properties

        /// <summary>
        /// Access token expiration date; or <c>null</c> if token does not expire
        /// </summary>
        public DateTime? Expires { get; }

        /// <summary>
        /// List of access token scope identifiers
        /// </summary>
        public string[] Scope { get; }

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
                Scope = scope.Split(null);
        }

        #endregion

        #region Methods

        /// <summary>
        /// Creates access token from data returned by authentication server.
        /// </summary>
        /// <param name="obj">An object representing access token as returned by the authentication server</param>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-5.1"/>
        public static AccessToken Create(Dictionary<string, object> obj)
        {
            // Get token type.
            var token_type = eduJSON.Parser.GetValue<string>(obj, "token_type");
            switch (token_type.ToLowerInvariant())
            {
                case "bearer": return new BearerToken(obj);
                default: throw new UnsupportedTokenTypeException(token_type);
            }
        }

        /// <summary>
        /// Adds token to request
        /// </summary>
        /// <param name="req">Web request</param>
        public virtual void AddToRequest(HttpWebRequest req)
        {
        }

        #endregion

        #region ISerializable Support

        protected AccessToken(SerializationInfo info, StreamingContext context)
        {
            // Load access token.
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
            Scope = (string[])info.GetValue("Scope", typeof(string[]));
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
            info.AddValue("Scope", Scope);
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
