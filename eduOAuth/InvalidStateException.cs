/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017-2019 The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Runtime.Serialization;

namespace eduOAuth
{
    /// <summary>
    /// Response and request states are different.
    /// </summary>
    [Serializable]
    public class InvalidStateException : eduJSON.ParameterException
    {
        #region Constructors

        /// <summary>
        /// Constructs an exception
        /// </summary>
        public InvalidStateException() :
            this(Resources.Strings.ErrorInvalidState)
        {
        }

        /// <summary>
        /// Constructs an exception
        /// </summary>
        /// <param name="message">Exception message</param>
        public InvalidStateException(string message) :
            base(message, null)
        {
        }

        #endregion

        #region ISerializable Support

        /// <summary>
        /// Deserialize object.
        /// </summary>
        /// <param name="info">The <see cref="SerializationInfo"/> populated with data.</param>
        /// <param name="context">The source of this deserialization.</param>
        protected InvalidStateException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        #endregion
    }
}
