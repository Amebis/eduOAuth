/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Runtime.Serialization;
using System.Security.Permissions;

namespace eduOAuth
{
    /// <summary>
    /// The received token type is not supported.
    /// </summary>
    [Serializable]
    public class UnsupportedTokenTypeException : ApplicationException, ISerializable
    {
        #region Properties

        /// <summary>
        /// The error message
        /// </summary>
        public override string Message => String.Format(Resources.Strings.ErrorTokenType, base.Message, Type);

        /// <summary>
        /// Token type received
        /// </summary>
        public string Type { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Constructs an exception
        /// </summary>
        /// <param name="type">Token type</param>
        public UnsupportedTokenTypeException(string type) :
            this(Resources.Strings.ErrorUnsupportedTokenType, type)
        {
        }

        /// <summary>
        /// Constructs an exception
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="type">Token type</param>
        public UnsupportedTokenTypeException(string message, string type) :
            base(message)
        {
            Type = type;
        }

        #endregion

        #region ISerializable Support

        protected UnsupportedTokenTypeException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            Type = (string)info.GetValue("Type", typeof(string));
        }

        /// <inheritdoc/>
        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("Type", Type);
        }

        #endregion
    }
}
