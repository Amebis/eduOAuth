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
    /// Unacceptable or missing parameter.
    /// </summary>
    [Serializable]
    public class ParameterException : ApplicationException
    {
        public ParameterException(string message, string parameter) :
            base(message)
        {
            ParameterName = parameter;
        }

        protected ParameterException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            ParameterName = (string)info.GetValue("ParameterName", typeof(string));
        }

        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("ParameterName", ParameterName);
        }

        /// <summary>
        /// The error message
        /// </summary>
        public override string Message => ParameterName != null ? String.Format("{0} - {1}", base.Message, ParameterName) : base.Message;

        /// <summary>
        /// Parameter name
        /// </summary>
        public string ParameterName { get; }
    }
}
