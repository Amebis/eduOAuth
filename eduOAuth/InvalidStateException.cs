/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOAuth
{
    /// <summary>
    /// Response state and request state are different.
    /// </summary>
    [Serializable]
    class InvalidStateException : ApplicationException
    {
        public InvalidStateException()
        {

        }
    }
}
