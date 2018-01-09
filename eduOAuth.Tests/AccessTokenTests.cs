/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace eduOAuth.Tests
{
    [TestClass()]
    public class AccessTokenTests
    {
        private static readonly string _json = "{\"access_token\":\"dxG1Z07kbr15a8nypuCk7OSf2USL7DlqMJCSicSR1oX\\/6EX3UJE6iboB78EeQwol4zZm7uKaT7B9tk0LZl2XBHsidHlwZSI6ImFjY2Vzc190b2tlbiIsImF1dGhfa2V5IjoiYzQxNDdmMmRlZjljM2ZlOTkzMThlMjEyMzc5NGE5MTMiLCJ1c2VyX2lkIjoiZDRhYzZiMDQ0MzA1NWZiNWE3MTQyMDM3ZDZhZGZiMzU1OGNiYzcxZCIsImNsaWVudF9pZCI6Im9yZy5lZHV2cG4uYXBwLndpbmRvd3MiLCJzY29wZSI6ImNvbmZpZyIsImV4cGlyZXNfYXQiOiIyMDE4LTAxLTA5IDEwOjQ4OjU5In0=\",\"refresh_token\":\"E\\/7pOay3LzBDA+WHsC78q60I6ujnbwqnAVA8ac2e07eFYfS4gApR1K+rwt5DUaERj5xjkguVqliNO2HoPQYxAHsidHlwZSI6InJlZnJlc2hfdG9rZW4iLCJhdXRoX2tleSI6ImM0MTQ3ZjJkZWY5YzNmZTk5MzE4ZTIxMjM3OTRhOTEzIiwidXNlcl9pZCI6ImQ0YWM2YjA0NDMwNTVmYjVhNzE0MjAzN2Q2YWRmYjM1NThjYmM3MWQiLCJjbGllbnRfaWQiOiJvcmcuZWR1dnBuLmFwcC53aW5kb3dzIiwic2NvcGUiOiJjb25maWcifQ==\",\"token_type\":\"bearer\",\"expires_in\":3600}";
        private static readonly Dictionary<string, object> _obj = (Dictionary<string, object>)eduJSON.Parser.Parse(_json);

        [TestMethod()]
        public void AccessTokenTest()
        {
            var access_token = new BearerToken(_obj);

            Assert.IsTrue(DateTime.Now <= access_token.Expires);
            Assert.IsNull(access_token.Scope);
        }

        [TestMethod()]
        public void AccessTokenSerializationTest()
        {
            AccessToken
                token1 = new BearerToken(_obj),
                token2 = AccessToken.FromBase64String(token1.ToBase64String());

            Assert.AreEqual(token1, token2);
            Assert.IsTrue(token1.Expires == token2.Expires);
            Assert.IsTrue((token1.Scope == null) == (token2.Scope == null));
            Assert.IsTrue(token1.Scope == null || token1.Scope.SetEquals(token2.Scope));
        }
    }
}
