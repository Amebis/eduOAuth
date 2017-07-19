/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Security;

namespace eduOAuth
{
    public class AccessToken : IDisposable
    {
        #region Fields

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
            token = new SecureString();
            foreach (var c in eduJSON.Parser.GetValue<string>(obj, "access_token"))
                token.AppendChar(c);
            token.MakeReadOnly();

            // Get expiration date.
            if (eduJSON.Parser.GetValue(obj, "expires_in", out int expires_in))
                Expires = DateTime.Now.AddSeconds(expires_in);

            // Get refresh token
            if (eduJSON.Parser.GetValue(obj, "refresh_token", out string refresh_token))
            {
                refresh = new SecureString();
                foreach (var c in refresh_token)
                    refresh.AppendChar(c);
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
