/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Security;

namespace eduOAuth
{
    public class AccessToken : IDisposable
    {
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
        /// Access token
        /// </summary>
        private SecureString token;

        /// <summary>
        /// Access token expiration date; or <c>null</c> if token does not expire
        /// </summary>
        public DateTime? Expires { get; }

        /// <summary>
        /// List of access token scope identifiers
        /// </summary>
        public string[] Scope { get; }

        /// <summary>
        /// Refresh token
        /// </summary>
        private SecureString refresh;

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
