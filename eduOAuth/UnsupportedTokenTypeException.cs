/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Runtime.Serialization;
using System.Security.Permissions;

namespace eduOAuth
{
    /// <summary>
    /// The received token type is not supported
    /// </summary>
    [Serializable]
    public class UnsupportedTokenTypeException : ApplicationException
    {
        public UnsupportedTokenTypeException(string type)
        {
            Type = type;
        }

        protected UnsupportedTokenTypeException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            Type = (string)info.GetValue("Type", typeof(string));
        }

        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("Type", Type);
        }

        /// <summary>
        /// Token type received
        /// </summary>
        public string Type { get; }
    }
}
