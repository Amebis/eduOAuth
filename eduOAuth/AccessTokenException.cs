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
    /// OAuth authorization server returned an error.
    /// </summary>
    /// <see cref="https://tools.ietf.org/html/rfc6749#section-5.2"/>
    [Serializable]
    public class AccessTokenException : ApplicationException, ISerializable
    {
        #region Data Types

        /// <summary>
        /// An error type
        /// </summary>
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

        #endregion

        #region Properties

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
                        msg = Resources.Strings.ErrorAccessTokenInvalidRequest;
                        break;

                    case ErrorCodeType.InvalidClient:
                        msg = Resources.Strings.ErrorAccessTokenInvalidClient;
                        break;

                    case ErrorCodeType.InvalidGrant:
                        msg = Resources.Strings.ErrorAccessTokenInvalidGrant;
                        break;

                    case ErrorCodeType.UnauthorizedClient:
                        msg = Resources.Strings.ErrorAccessTokenUnauthorizedClient;
                        break;

                    case ErrorCodeType.UnsupportedGrantType:
                        msg = Resources.Strings.ErrorAccessTokenUnsupportedGrantType;
                        break;

                    case ErrorCodeType.InvalidScope:
                        msg = Resources.Strings.ErrorAccessTokenInvalidScope;
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

        /// <summary>
        /// Error code
        /// </summary>
        public ErrorCodeType ErrorCode { get; }

        /// <summary>
        /// Error URI
        /// </summary>
        public Uri ErrorUri { get; }

        #endregion

        #region Constructors

        /// <summary>
        /// Creates an exception
        /// </summary>
        /// <param name="error">An RFC6749 error identifier</param>
        /// <param name="error_description">Human-readable text providing additional information</param>
        /// <param name="error_uri">A URI identifying a human-readable web page with information about the error</param>
        public AccessTokenException(string error, string error_description, string error_uri) :
            base(error_description)
        {
            switch (error.ToLowerInvariant())
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

        #endregion

        #region ISerializable Support

        protected AccessTokenException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            ErrorCode = (ErrorCodeType)info.GetValue("ErrorCode", typeof(ErrorCodeType));
            ErrorUri = (Uri)info.GetValue("ErrorUri", typeof(Uri));
        }

        /// <inheritdoc/>
        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("ErrorCode", ErrorCode);
            info.AddValue("ErrorUri", ErrorUri);
        }

        #endregion
    }
}
