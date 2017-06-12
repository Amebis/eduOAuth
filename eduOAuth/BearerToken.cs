﻿/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System.Collections.Generic;

namespace eduOAuth
{
    public class BearerToken : AccessToken
    {
        /// <summary>
        /// Bearer access token (RFC 6750)
        /// </summary>
        /// <param name="obj">An object representing access token as returned by the authentication server</param>
        /// <see cref="https://tools.ietf.org/html/rfc6750"/>
        public BearerToken(Dictionary<string, object> obj) :
            base(obj)
        {

        }
    }
}
