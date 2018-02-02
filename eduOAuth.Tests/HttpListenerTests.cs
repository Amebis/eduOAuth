/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Net;
using System.Text;

namespace eduOAuth.Tests
{
    [TestClass()]
    public class HttpListenerTests
    {
        [TestMethod()]
        public void HttpListenerTest()
        {
            string uri_base = null;
            bool callback_called = false;
            var listener = new HttpListener(IPAddress.Loopback, 0);
            listener.HttpCallback += (object sender, HttpCallbackEventArgs e) =>
            {
                Assert.AreEqual(uri_base + "/callback?test123", e.Uri.AbsoluteUri);
                callback_called = true;
            };

            listener.Start();
            try
            {
                uri_base = String.Format("http://{0}:{1}", IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);

                {
                    var request = (HttpWebRequest)WebRequest.Create(uri_base + "/callback?test123");
                    request.Method = "POST";
                    request.ContentType = "text/plain";
                    var data = Encoding.ASCII.GetBytes("This is a test content.");
                    using (var req_stream = request.GetRequestStream())
                        req_stream.Write(data, 0, data.Length);

                    using (var response = (HttpWebResponse)request.GetResponse())
                    {
                        Assert.IsTrue(callback_called);
                        Assert.AreEqual("text/html; charset=UTF-8", response.ContentType);

                        using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8, false))
                            reader.ReadToEnd();
                    }
                }

                {
                    var request = (HttpWebRequest)WebRequest.Create(uri_base + "/finished");
                    using (var response = (HttpWebResponse)request.GetResponse())
                        Assert.AreEqual("text/html; charset=UTF-8", response.ContentType);
                }

                {
                    var request = (HttpWebRequest)WebRequest.Create(uri_base + "/script.js");
                    using (var response = (HttpWebResponse)request.GetResponse())
                        Assert.AreEqual("text/javascript", response.ContentType);
                }

                {
                    var request = (HttpWebRequest)WebRequest.Create(uri_base + "/style.css");
                    using (var response = (HttpWebResponse)request.GetResponse())
                        Assert.AreEqual("text/css", response.ContentType);
                }

                {
                    var request = (HttpWebRequest)WebRequest.Create(uri_base + "/nonexisting");
                    try
                    {
                        using (request.GetResponse())
                        {
                        }
                        Assert.Fail("\"404\" tolerated");
                    }
                    catch (WebException ex)
                    {
                        Assert.IsTrue(ex.Response is HttpWebResponse response && response.StatusCode == HttpStatusCode.NotFound);
                    }
                }
            }
            finally
            {
                listener.Stop();
            }
        }
    }
}
