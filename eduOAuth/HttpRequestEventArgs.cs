/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017-2019 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.IO;

namespace eduOAuth
{
    /// <summary>
    /// <see cref="HttpListener.HttpRequest"/> event parameters
    /// </summary>
    public class HttpRequestEventArgs : EventArgs
    {
        #region Properties

        /// <summary>
        /// URI
        /// </summary>
        public Uri Uri { get; }

        /// <summary>
        /// Response content MIME type
        /// </summary>
        public string Type { get; set; }

        /// <summary>
        /// Response content data
        /// </summary>
        public Stream Content { get; set; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an event arguments
        /// </summary>
        /// <param name="uri">URI</param>
        public HttpRequestEventArgs(Uri uri)
        {
            Uri = uri;
        }

        #endregion
    }
}
