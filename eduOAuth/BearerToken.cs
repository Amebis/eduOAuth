/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.Serialization;

namespace eduOAuth
{
    /// <summary>
    /// Bearer access token
    /// </summary>
    [Serializable]
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

        /// <inheritdoc/>
        public override void AddToRequest(WebRequest request)
        {
            request.Headers.Add(string.Format("Authorization: Bearer {0}", new NetworkCredential("", _token).Password));
        }

        #endregion

        #region ISerializable Support

        protected BearerToken(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        #endregion
    }
}
