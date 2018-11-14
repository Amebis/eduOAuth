/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017-2018 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;

namespace eduOAuth
{
    /// <summary>
    /// <see cref="HttpListener.HttpCallback"/> event parameters
    /// </summary>
    public class HttpCallbackEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// URI
        /// </summary>
        public Uri Uri { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="uri">URI</param>
        public HttpCallbackEventArgs(Uri uri)
        {
            Uri = uri;
        }

        #endregion
    }
}
