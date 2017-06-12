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
    /// Parameter type is invalid
    /// </summary>
    [Serializable]
    public class InvalidTypeParameterException : ParameterException
    {
        public InvalidTypeParameterException(string parameter, Type expected_type, Type provided_type) :
            base(parameter)
        {
            ExpectedType = expected_type;
            ProvidedType = provided_type;
        }

        protected InvalidTypeParameterException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            ExpectedType = (Type)info.GetValue("ExpectedType", typeof(Type));
            ProvidedType = (Type)info.GetValue("ProvidedType", typeof(Type));
        }

        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("ExpectedType", ExpectedType);
            info.AddValue("ProvidedType", ProvidedType);
        }

        /// <summary>
        /// The expected type of parameter
        /// </summary>
        public Type ExpectedType { get; }

        /// <summary>
        /// The provided type of parameter
        /// </summary>
        public Type ProvidedType { get; }
    }
}
