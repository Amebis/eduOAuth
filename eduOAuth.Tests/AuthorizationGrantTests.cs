using eduOAuth;
/*
eduOAuth - An OAuth 2.0 Client for eduVPN (and beyond)

Copyright: 2017, The Commons Conservancy eduVPN Programme
SPDX-License-Identifier: GPL-3.0+
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Web;

namespace eduOAuth.Tests
{
    [TestClass()]
    public class AuthorizationGrantTests
    {
        [TestMethod()]
        public void AuthorizationURITest()
        {
            var ag = new AuthorizationGrant()
            {
                AuthorizationEndpoint = new Uri("https://test.eduvpn.org/?param=1"),
                RedirectEndpoint = new Uri("org.eduvpn.app:/api/callback"),
                ClientID = "org.eduvpn.app",
                CodeChallengeAlgorithm = AuthorizationGrant.CodeChallengeAlgorithmType.S256,
                Scope = new List<string>() { "scope1", "scope2" },
            };

            var uri_builder = new UriBuilder(ag.AuthorizationURI);
            Assert.AreEqual("https", uri_builder.Scheme);
            Assert.AreEqual("test.eduvpn.org", uri_builder.Host);
            Assert.AreEqual("/", uri_builder.Path);

            var query = HttpUtility.ParseQueryString(uri_builder.Query);
            Assert.AreEqual("1", query["param"]);
            Assert.AreEqual("code", query["response_type"]);
            Assert.AreEqual("org.eduvpn.app", query["client_id"]);
            Assert.AreEqual("org.eduvpn.app:/api/callback", query["redirect_uri"]);
            CollectionAssert.AreEqual(new List<string>() { "scope1", "scope2" }, query["scope"].Split(null));
            Assert.IsTrue(AuthorizationGrant.Base64URLDecodeNoPadding(query["state"]).Length > 0);
            Assert.AreEqual("S256", query["code_challenge_method"]);
            Assert.IsTrue(AuthorizationGrant.Base64URLDecodeNoPadding(query["code_challenge"]).Length > 0);
        }

        [TestMethod()]
        public void Base64URLEncodeNoPaddingTest()
        {
            Assert.AreEqual("ESM", AuthorizationGrant.Base64URLEncodeNoPadding(new byte[] { 0x11, 0x23 }));
            Assert.AreEqual("HE3j", AuthorizationGrant.Base64URLEncodeNoPadding(new byte[] { 0x1c, 0x4d, 0xe3 }));
            Assert.AreEqual("LqhVsL4", AuthorizationGrant.Base64URLEncodeNoPadding(new byte[] { 0x2e, 0xa8, 0x55, 0xb0, 0xbe }));
            Assert.AreEqual("DEZGb5gDRyzWvS4oDmEwX8F-h8Lcdo6fdBgzsI_9-No", AuthorizationGrant.Base64URLEncodeNoPadding(new byte[] {
                0x0c, 0x46, 0x46, 0x6f, 0x98, 0x03, 0x47, 0x2c, 0xd6, 0xbd, 0x2e, 0x28, 0x0e, 0x61, 0x30, 0x5f,
                0xc1, 0x7e, 0x87, 0xc2, 0xdc, 0x76, 0x8e, 0x9f, 0x74, 0x18, 0x33, 0xb0, 0x8f, 0xfd, 0xf8, 0xda,
            }));
        }

        [TestMethod()]
        public void Base64URLDecodeNoPaddingTest()
        {
            CollectionAssert.AreEqual(new byte[] { 0x11, 0x23 }, AuthorizationGrant.Base64URLDecodeNoPadding("ESM"));
            CollectionAssert.AreEqual(new byte[] { 0x1c, 0x4d, 0xe3 }, AuthorizationGrant.Base64URLDecodeNoPadding("HE3j"));
            CollectionAssert.AreEqual(new byte[] { 0x2e, 0xa8, 0x55, 0xb0, 0xbe }, AuthorizationGrant.Base64URLDecodeNoPadding("LqhVsL4"));
            CollectionAssert.AreEqual(new byte[] {
                0x0c, 0x46, 0x46, 0x6f, 0x98, 0x03, 0x47, 0x2c, 0xd6, 0xbd, 0x2e, 0x28, 0x0e, 0x61, 0x30, 0x5f,
                0xc1, 0x7e, 0x87, 0xc2, 0xdc, 0x76, 0x8e, 0x9f, 0x74, 0x18, 0x33, 0xb0, 0x8f, 0xfd, 0xf8, 0xda,
            }, AuthorizationGrant.Base64URLDecodeNoPadding("DEZGb5gDRyzWvS4oDmEwX8F-h8Lcdo6fdBgzsI_9-No"));
        }
    }
}