﻿/*
    eduVPN - VPN for education and research

    Copyright: 2017-2021 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using eduEx.Async;
using System;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Security.Permissions;
using System.Text;
using System.Threading;

namespace eduOAuth
{
    /// <summary>
    /// Unexpected parameter type.
    /// </summary>
    [Serializable]
    public class WebExceptionEx : WebException
    {
        #region Properties

        /// <summary>
        /// The response text
        /// </summary>
        public string ResponseText { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an exception
        /// </summary>
        /// <param name="ex">Original <see cref="WebException"/></param>
        /// <param name="ct">The token to monitor for cancellation requests</param>
        public WebExceptionEx(WebException ex, CancellationToken ct = default) :
            base(ex.Message, ex.InnerException, ex.Status, ex.Response)
        {
            if (ex.Response is HttpWebResponse httpResponse)
            {
                try
                {
                    // Determine response encoding.
                    var charset = httpResponse.CharacterSet;
                    var encoding = !string.IsNullOrEmpty(charset) ?
                        Encoding.GetEncoding(charset) :
                        Encoding.UTF8;

                    // Read the response from server and save it.
                    using (var streamReader = new StreamReader(httpResponse.GetResponseStream(), encoding))
                        ResponseText = streamReader.ReadToEnd(ct);
                }
                catch { }
            }
        }

        #endregion

        #region Methods

        /// <inheritdoc/>
        public override string ToString()
        {
            return string.IsNullOrEmpty(ResponseText) ?
                base.ToString() :
                base.ToString() + "\r\n-----BEGIN RESPONSE-----\r\n" + ResponseText + "\r\n-----END RESPONSE-----\r\n";
        }

        #endregion

        #region ISerializable Support

        /// <summary>
        /// Deserialize object.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> populated with data.</param>
        /// <param name="context">The source of this deserialization.</param>
        protected WebExceptionEx(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            ResponseText = (string)info.GetValue("ResponseText", typeof(string));
        }

        /// <inheritdoc/>
        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("ResponseText", ResponseText);
        }

        #endregion
    }
}
