/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web;

namespace eduOAuth
{
    public class HttpListener : TcpListener
    {
        #region Fields

        /// <summary>
        /// Filename extension - MIME type dictionary
        /// </summary>
        private static readonly Dictionary<string, string> _mime_types = new Dictionary<string, string>()
        {
            { ".css", "text/css" },
            { ".ico", "image/x-icon" },
            { ".js" , "text/javascript" },
        };

        #endregion

        #region Constructors

        /// <inheritdoc/>
        public HttpListener(IPEndPoint localEP) :
            base(localEP)
        { }

        /// <inheritdoc/>
        public HttpListener(IPAddress localaddr, int port) :
            base(localaddr, port)
        { }

        #endregion

        #region Methods

        /// <summary>
        /// Starts listening and accepting clients in the background
        /// </summary>
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "Stream tolerates multiple disposes.")]
        public new void Start()
        {
            // Launch TCP listener.
            base.Start();
            new Thread(new ThreadStart(
                () =>
                {
                    for (; ; )
                    {
                        // Wait for the agent request and accept it.
                        TcpClient client = null;
                        try { client = AcceptTcpClient(); }
                        catch (InvalidOperationException) { break; }
                        catch (SocketException) { break; }
                        new Thread(new ThreadStart(
                            () =>
                            {
                                try
                                {
                                    // Receive agent request.
                                    string request = null;
                                    using (var memory_stream = new MemoryStream())
                                    {
                                        var stream = client.GetStream();
                                        var buffer = new byte[client.ReceiveBufferSize];
                                        while (stream.DataAvailable)
                                        {
                                            // Read available data.
                                            var bytes_read = stream.Read(buffer, 0, buffer.Length);
                                            if (bytes_read == 0)
                                                break;

                                            // Append it to the memory stream.
                                            memory_stream.Write(buffer, 0, bytes_read);
                                        }

                                        request = Encoding.UTF8.GetString(memory_stream.ToArray());
                                    }

                                    var assembly = Assembly.GetExecutingAssembly();
                                    try
                                    {
                                        var request_headers = request.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
                                        var request_line = request_headers[0].Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                                        switch (request_line[0].ToUpperInvariant())
                                        {
                                            case "GET":
                                            case "POST":
                                                break;
                                            default:
                                                throw new HttpException(405, string.Format(Resources.Strings.ErrorHttp405, request_line[0]));
                                        }

                                        var uri = new Uri(string.Format("http://{0}:{1}{2}", IPAddress.Loopback, ((IPEndPoint)LocalEndpoint).Port, request_line[1]));
                                        switch (uri.AbsolutePath)
                                        {
                                            case "/callback":
                                                {
                                                    OnHttpCallback(client, new HttpCallbackEventArgs(uri));

                                                    // Redirect agent to the finished page. This clears the explicit OAuth callback URI from agent location, and prevents page refreshes to reload /callback with stale data.
                                                    using (var writer = new StreamWriter(client.GetStream(), new UTF8Encoding(false)))
                                                        writer.Write(string.Format("HTTP/1.0 301 Moved Permanently\r\nLocation: http://{0}:{1}/finished\r\n\r\n", IPAddress.Loopback, ((IPEndPoint)LocalEndpoint).Port));
                                                }
                                                break;

                                            case "/finished":
                                                {
                                                    // Send response to the agent.
                                                    using (var stream = assembly.GetManifestResourceStream("eduOAuth.Resources.Html.finished.html"))
                                                    using (var reader = new StreamReader(stream, true))
                                                    {
                                                        var response = string.Format(reader.ReadToEnd(),
                                                            Thread.CurrentThread.CurrentUICulture.Name,
                                                            HttpUtility.HtmlEncode(Resources.Strings.HtmlFinishedTitle),
                                                            HttpUtility.HtmlEncode(Resources.Strings.HtmlFinishedDescription));
                                                        using (var writer = new StreamWriter(client.GetStream(), new UTF8Encoding(false)))
                                                            writer.Write(string.Format("HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {0}\r\n\r\n{1}", response.Length, response));
                                                    }
                                                }
                                                break;

                                            case "/favicon.ico":
                                            case "/script.js":
                                            case "/style.css":
                                                {
                                                    // Send static content.
                                                    using (var stream = assembly.GetManifestResourceStream("eduOAuth.Resources.Html" + uri.AbsolutePath.Replace('/', '.')))
                                                    using (var response_stream = client.GetStream())
                                                    {
                                                        var headers = Encoding.ASCII.GetBytes(string.Format("HTTP/1.0 200 OK\r\nContent-Type: {0}\r\nContent-Length: {1}\r\n\r\n",
                                                            _mime_types[Path.GetExtension(uri.LocalPath)],
                                                            stream.Length));
                                                        response_stream.Write(headers, 0, headers.Length);
                                                        stream.CopyTo(response_stream);
                                                    }
                                                }
                                                break;

                                            default:
                                                throw new HttpException(404, string.Format(Resources.Strings.ErrorHttp404, uri.AbsolutePath));
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        // Send response to the agent.
                                        var status_code = ex is HttpException ex_http ? ex_http.GetHttpCode() : 500;
                                        using (var stream = assembly.GetManifestResourceStream("eduOAuth.Resources.Html.error.html"))
                                        using (var reader = new StreamReader(stream, true))
                                        {
                                            string response;
                                            try {
                                                response = string.Format(reader.ReadToEnd(),
                                                    Thread.CurrentThread.CurrentUICulture.Name,
                                                    HttpUtility.HtmlEncode(Resources.Strings.HtmlErrorTitle),
                                                    HttpUtility.HtmlEncode(ex.Message),
                                                    HttpUtility.HtmlEncode(Resources.Strings.HtmlErrorDescription));
                                            }
                                            catch { response = HttpUtility.HtmlEncode(ex.ToString()); }
                                            using (var writer = new StreamWriter(client.GetStream(), new UTF8Encoding(false)))
                                                writer.Write(string.Format("HTTP/1.0 {0} Error\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {1}\r\n\r\n{2}", status_code, response.Length, response));
                                        }
                                    }
                                }
                                catch { }
                            }
                        )).Start();
                    }
                })).Start();
        }

        /// <summary>
        /// Raises <c>Callback</c> event
        /// </summary>
        /// <param name="sender">Event sender - a <c>System.Net.Sockets.TcpClient</c> object representing agent client</param>
        /// <param name="e">Event parameters</param>
        protected virtual void OnHttpCallback(object sender, HttpCallbackEventArgs e)
        {
            HttpCallback?.Invoke(sender, e);
        }

        /// <summary>
        /// Raised when OAuth callback received
        /// </summary>
        /// <remarks>Sender is the TCP client <c>System.Net.Sockets.TcpClient</c>.</remarks>
        public event EventHandler<HttpCallbackEventArgs> HttpCallback;

        #endregion
    }
}
