/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017-2023 The Commons Conservancy
    SPDX-License-Identifier: GPL-3.0+
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace eduOAuth.Tests
{
    [TestClass()]
    public class AccessTokenTests
    {
        [TestMethod()]
        public void AccessTokenSerializationTest()
        {
            AccessToken
                token1 = new BearerToken(Global.AccessTokenObj, DateTimeOffset.Now),
                token2 = AccessToken.FromBase64String(token1.ToBase64String());
            Assert.AreEqual(token1, token2);
            Assert.IsTrue(token1.Authorized == token2.Authorized);
            Assert.IsTrue(token1.Expires == token2.Expires);
            Assert.IsTrue((token1.Scope == null) == (token2.Scope == null));
            Assert.IsTrue(token1.Scope == null || token1.Scope.SetEquals(token2.Scope));
        }
    }
}
