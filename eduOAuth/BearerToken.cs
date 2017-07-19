/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System.Collections.Generic;
using System.Net;

namespace eduOAuth
{
    public class BearerToken : AccessToken
    {
        #region Constructors

        /// <summary>
        /// Bearer access token (RFC 6750)
        /// </summary>
        /// <param name="obj">An object representing access token as returned by the authentication server</param>
        /// <see cref="https://tools.ietf.org/html/rfc6750"/>
        public BearerToken(Dictionary<string, object> obj) :
            base(obj)
        {
        }

        #endregion

        #region Methods

        public override void AddToRequest(HttpWebRequest req)
        {
            req.Headers.Add(string.Format("Authorization: Bearer {0}", new NetworkCredential("", token).Password));
        }

        #endregion
    }
}
