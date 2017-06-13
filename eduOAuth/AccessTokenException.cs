/*
    eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Security.Permissions;

namespace eduOAuth
{
    /// <summary>
    /// OAuth authorization server returned an error.
    /// </summary>
    [Serializable]
    class AccessTokenException : ApplicationException
    {
        public AccessTokenException(string error, string error_description, string error_uri) :
            base(error_description)
        {
            switch (((string)error).ToLowerInvariant())
            {
                case "invalid_request":
                    ErrorCode = ErrorCodeType.InvalidRequest;
                    break;

                case "invalid_client":
                    ErrorCode = ErrorCodeType.InvalidClient;
                    break;

                case "invalid_grant":
                    ErrorCode = ErrorCodeType.InvalidGrant;
                    break;

                case "unauthorized_client":
                    ErrorCode = ErrorCodeType.UnauthorizedClient;
                    break;

                case "unsupported_grant_type":
                    ErrorCode = ErrorCodeType.UnsupportedGrantType;
                    break;

                case "invalid_scope":
                    ErrorCode = ErrorCodeType.InvalidScope;
                    break;

                default:
                    ErrorCode = ErrorCodeType.Unknown;
                    break;
            }

            if (error_uri != null)
                ErrorUri = new Uri(error_uri);
        }

        protected AccessTokenException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            ErrorCode = (ErrorCodeType)info.GetValue("ErrorCode", typeof(ErrorCodeType));
            ErrorUri = (Uri)info.GetValue("ErrorUri", typeof(Uri));
        }

        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("ErrorCode", ErrorCode);
            info.AddValue("ErrorUri", ErrorUri);
        }

        public static AccessTokenException Create(Dictionary<string, object> obj)
        {
            // Get error type.
            object error;
            if (obj.TryGetValue("error", out error))
            {
                if (error.GetType() != typeof(string))
                    throw new InvalidParameterTypeException("error", typeof(string), error.GetType());
            }
            else
                throw new MissingParameterException("error");

            // Get error description.
            object error_description;
            if (obj.TryGetValue("error_description", out error_description))
            {
                if (error_description.GetType() != typeof(string))
                    throw new InvalidParameterTypeException("error_description", typeof(string), error_description.GetType());
            }

            // Get error URI.
            object error_uri;
            if (obj.TryGetValue("error_uri", out error_uri))
            {
                if (error_uri.GetType() != typeof(string))
                    throw new InvalidParameterTypeException("error_uri", typeof(string), error_uri.GetType());
            }

            return new AccessTokenException((string)error, (string)error_description, (string)error_uri);
        }

        /// <summary>
        /// The error message
        /// </summary>
        public override string Message
        {
            get
            {
                string msg;
                switch (ErrorCode)
                {
                    case ErrorCodeType.InvalidRequest:
                        msg = Resources.ErrorAccessTokenInvalidRequest;
                        break;

                    case ErrorCodeType.InvalidClient:
                        msg = Resources.ErrorAccessTokenInvalidClient;
                        break;

                    case ErrorCodeType.InvalidGrant:
                        msg = Resources.ErrorAccessTokenInvalidGrant;
                        break;

                    case ErrorCodeType.UnauthorizedClient:
                        msg = Resources.ErrorAccessTokenUnauthorizedClient;
                        break;

                    case ErrorCodeType.UnsupportedGrantType:
                        msg = Resources.ErrorAccessTokenUnsupportedGrantType;
                        break;

                    case ErrorCodeType.InvalidScope:
                        msg = Resources.ErrorAccessTokenInvalidScope;
                        break;

                    default:
                        msg = null;
                        break;
                }

                if (base.Message != null)
                    msg = msg != null ? String.Format("{0}\n{1}", msg, base.Message) : base.Message;

                if (ErrorUri != null)
                    msg = msg != null ? String.Format("{0}\n{1}", msg, ErrorUri.ToString()) : ErrorUri.ToString();

                return msg;
            }
        }

        public enum ErrorCodeType
        {
            /// <summary>
            /// Unknown reason of failure
            /// </summary>
            Unknown,

            /// <summary>
            /// The request is missing a required parameter, includes an
            /// unsupported parameter value (other than grant type),
            /// repeats a parameter, includes multiple credentials,
            /// utilizes more than one mechanism for authenticating the
            /// client, or is otherwise malformed.
            /// </summary>
            InvalidRequest,

            /// <summary>
            /// Client authentication failed (e.g., unknown client, no
            /// client authentication included, or unsupported
            /// authentication method). The authorization server MAY
            /// return an HTTP 401 (Unauthorized) status code to indicate
            /// which HTTP authentication schemes are supported. If the
            /// client attempted to authenticate via the "Authorization"
            /// request header field, the authorization server MUST
            /// respond with an HTTP 401 (Unauthorized) status code and
            /// include the "WWW-Authenticate" response header field
            /// matching the authentication scheme used by the client.
            /// </summary>
            InvalidClient,

            /// <summary>
            /// The provided authorization grant (e.g., authorization
            /// code, resource owner credentials) or refresh token is
            /// invalid, expired, revoked, does not match the redirection
            /// URI used in the authorization request, or was issued to
            /// another client.
            /// </summary>
            InvalidGrant,

            /// <summary>
            /// The authenticated client is not authorized to use this
            /// authorization grant type.
            /// </summary>
            UnauthorizedClient,

            /// <summary>
            /// The authorization grant type is not supported by the
            /// authorization server.
            /// </summary>
            UnsupportedGrantType,

            /// <summary>
            /// The requested scope is invalid, unknown, malformed, or
            /// exceeds the scope granted by the resource owner.
            /// </summary>
            InvalidScope,
        }

        /// <summary>
        /// Error code
        /// </summary>
        public ErrorCodeType ErrorCode { get; }

        /// <summary>
        /// Error URI
        /// </summary>
        public Uri ErrorUri { get; }
    }
}
