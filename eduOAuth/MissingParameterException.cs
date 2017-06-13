/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOAuth
{
    /// <summary>
    /// A required parameter is missing.
    /// </summary>
    [Serializable]
    public class MissingParameterException : ParameterException
    {
        public MissingParameterException(string parameter) :
            base(Resources.ErrorMissingParameter, parameter)
        {
        }
    }
}
