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
            object access_token;
            if (obj.TryGetValue("access_token", out access_token))
            {
                if (access_token.GetType() == typeof(string))
                {
                    token = new SecureString();
                    foreach (var c in (string)access_token)
                        token.AppendChar(c);
                    token.MakeReadOnly();
                }
                else
                    throw new eduJSON.InvalidParameterTypeException("access_token", typeof(string), access_token.GetType());
            }
            else
                throw new eduJSON.MissingParameterException("access_token");

            // Get expiration date.
            object expires_in;
            if (obj.TryGetValue("expires_in", out expires_in))
            {
                if (expires_in.GetType() == typeof(int))
                    Expires = DateTime.Now.AddSeconds((int)expires_in);
                else
                    throw new eduJSON.InvalidParameterTypeException("expires_in", typeof(int), expires_in.GetType());
            }

            // Get refresh token
            object refresh_token;
            if (obj.TryGetValue("refresh_token", out refresh_token))
            {
                if (refresh_token.GetType() == typeof(string))
                {
                    refresh = new SecureString();
                    foreach (var c in (string)refresh_token)
                        refresh.AppendChar(c);
                    refresh.MakeReadOnly();
                } else
                    throw new eduJSON.InvalidParameterTypeException("refresh_token", typeof(string), refresh_token.GetType());
            }

            // Get scope
            object scope;
            if (obj.TryGetValue("scope", out scope))
            {
                if (scope.GetType() == typeof(string))
                    Scope = ((string)scope).Split(null);
                else
                    throw new eduJSON.InvalidParameterTypeException("scope", typeof(string), scope.GetType());
            }
        }

        /// <summary>
        /// Creates access token from data returned by authentication server.
        /// </summary>
        /// <param name="obj">An object representing access token as returned by the authentication server</param>
        /// <see cref="https://tools.ietf.org/html/rfc6749#section-5.1"/>
        public static AccessToken Create(Dictionary<string, object> obj)
        {
            // Get token type.
            object token_type;
            if (obj.TryGetValue("token_type", out token_type))
                if (token_type.GetType() == typeof(string))
                {
                    switch (((string)token_type).ToLowerInvariant())
                    {
                        case "bearer": return new BearerToken(obj);
                        default: throw new UnsupportedTokenTypeException((string)token_type);
                    }
                } else
                    throw new eduJSON.InvalidParameterTypeException("token_type", typeof(string), token_type.GetType());
            else
                throw new eduJSON.MissingParameterException("token_type");
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
