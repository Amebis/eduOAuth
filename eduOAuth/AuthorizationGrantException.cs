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
    class AuthorizationGrantException : ApplicationException
    {
        public AuthorizationGrantException(string error, string error_description, string error_uri) :
            base(error_description)
        {
            switch (error.ToLowerInvariant())
            {
                case "invalid_request":
                    ErrorCode = ErrorCodeType.InvalidRequest;
                    break;

                case "unauthorized_client":
                    ErrorCode = ErrorCodeType.UnauthorizedClient;
                    break;

                case "access_denied":
                    ErrorCode = ErrorCodeType.AccessDenied;
                    break;

                case "unsupported_response_type":
                    ErrorCode = ErrorCodeType.UnsupportedResponseType;
                    break;

                case "invalid_scope":
                    ErrorCode = ErrorCodeType.InvalidScope;
                    break;

                case "server_error":
                    ErrorCode = ErrorCodeType.ServerError;
                    break;

                case "temporarily_unavailable":
                    ErrorCode = ErrorCodeType.TemporarilyUnavailable;
                    break;

                default:
                    ErrorCode = ErrorCodeType.Unknown;
                    break;
            }

            if (error_uri != null)
                ErrorUri = new Uri(error_uri);
        }

        protected AuthorizationGrantException(SerializationInfo info, StreamingContext context)
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
                        msg = Resources.ErrorAuthorizationGrantInvalidRequest;
                        break;

                    case ErrorCodeType.UnauthorizedClient:
                        msg = Resources.ErrorAuthorizationGrantUnauthorizedClient;
                        break;

                    case ErrorCodeType.AccessDenied:
                        msg = Resources.ErrorAuthorizationGrantAccessDenied;
                        break;

                    case ErrorCodeType.UnsupportedResponseType:
                        msg = Resources.ErrorAuthorizationGrantUnsupportedResponseType;
                        break;

                    case ErrorCodeType.InvalidScope:
                        msg = Resources.ErrorAuthorizationGrantInvalidScope;
                        break;

                    case ErrorCodeType.ServerError:
                        msg = Resources.ErrorAuthorizationGrantServerError;
                        break;

                    case ErrorCodeType.TemporarilyUnavailable:
                        msg = Resources.ErrorAuthorizationGrantTemporarilyUnavailable;
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
            /// Unknown error.
            /// </summary>
            Unknown,

            /// <summary>
            /// The request is missing a required parameter, includes an
            /// invalid parameter value, includes a parameter more than
            /// once, or is otherwise malformed.
            /// </summary>
            InvalidRequest,

            /// <summary>
            /// The client is not authorized to request an authorization
            /// code using this method.
            /// </summary>
            UnauthorizedClient,

            /// <summary>
            /// The resource owner or authorization server denied the
            /// request.
            /// </summary>
            AccessDenied,

            /// <summary>
            /// The authorization server does not support obtaining an
            /// authorization code using this method.
            /// </summary>
            UnsupportedResponseType,

            /// <summary>
            /// The requested scope is invalid, unknown, or malformed.
            /// </summary>
            InvalidScope,

            /// <summary>
            /// The authorization server encountered an unexpected
            /// condition that prevented it from fulfilling the request.
            /// (This error code is needed because a 500 Internal Server
            /// Error HTTP status code cannot be returned to the client
            /// via an HTTP redirect.)
            /// </summary>
            ServerError,

            /// <summary>
            /// The authorization server is currently unable to handle
            /// the request due to a temporary overloading or maintenance
            /// of the server.  (This error code is needed because a 503
            /// Service Unavailable HTTP status code cannot be returned
            /// to the client via an HTTP redirect.)
            /// </summary>
            TemporarilyUnavailable,
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
