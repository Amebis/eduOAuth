﻿/*
    eduOAuth - OAuth 2.0 Library for eduVPN (and beyond)

    Copyright: 2017, The Commons Conservancy eduVPN Programme
    SPDX-License-Identifier: GPL-3.0+
*/

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
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
    /// <summary>
    /// HTTP listener (server)
    /// </summary>
    public class HttpListener : TcpListener
    {
        #region Fields

        /// <summary>
        /// Executing assembly
        /// </summary>
        private static readonly Assembly _assembly = Assembly.GetExecutingAssembly();

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
                        new Thread(ProcessRequest).Start(client);
                    }
                })).Start();
        }

        /// <summary>
        /// Process a single HTTP request
        /// </summary>
        /// <param name="param">HTTP peer/client of type <see cref="System.Net.Sockets.TcpClient"/></param>
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "Stream tolerates multiple disposes.")]
        private void ProcessRequest(object param)
        {
            try
            {
                // Receive agent request.
                var client = (TcpClient)param;
                using (var stream = client.GetStream())
                    try
                    {
                        // Read HTTP request header.
                        var header_stream = new MemoryStream(8192);
                        var terminator = new byte[4];
                        var modulus = terminator.Length;
                        for (int i = 0; ; i = (i + 1) % modulus)
                        {
                            var data = stream.ReadByte();
                            if (data == -1)
                                break;
                            header_stream.WriteByte((byte)data);
                            terminator[i] = (byte)data;
                            if (terminator[(i + modulus - 3) % modulus] == '\r' &&
                                terminator[(i + modulus - 2) % modulus] == '\n' &&
                                terminator[(i + modulus - 1) % modulus] == '\r' &&
                                terminator[(i + modulus - 0) % modulus] == '\n')
                                break;
                        }
                        header_stream.Seek(0, SeekOrigin.Begin);

                        string[] request_line = null;
                        var request_headers = new NameValueCollection();
                        using (var reader = new StreamReader(header_stream, Encoding.UTF8, false))
                        {
                            // Parse start HTTP request line.
                            var line = reader.ReadLine();
                            if (String.IsNullOrEmpty(line))
                                throw new HttpException(400, String.Format(Resources.Strings.ErrorHttp400, line));
                            request_line = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                            if (request_line.Length < 3)
                                throw new HttpException(400, String.Format(Resources.Strings.ErrorHttp400, line));
                            switch (request_line[0].ToUpperInvariant())
                            {
                                case "GET":
                                case "POST":
                                    break;
                                default:
                                    throw new HttpException(405, String.Format(Resources.Strings.ErrorHttp405, request_line[0]));
                            }

                            // Parse request headers.
                            var header_separators = new char[] { ':' };
                            string field_name = null;
                            for (; ; )
                            {
                                line = reader.ReadLine();
                                if (String.IsNullOrEmpty(line))
                                    break;
                                else if (field_name == null || line[0] != ' ' && line[0] != '\t')
                                {
                                    var header = line.Split(header_separators, 2);
                                    if (header.Length < 2)
                                        throw new HttpException(400, String.Format(Resources.Strings.ErrorHttp400, line));
                                    field_name = header[0].Trim();
                                    if (request_headers[field_name] == null)
                                        request_headers.Add(field_name, header[1].Trim());
                                    else
                                        request_headers[field_name] += "," + header[1].Trim();
                                }
                                else
                                    request_headers[field_name] += " " + line.Trim();
                            }
                        }

                        var content_length_str = request_headers["Content-Length"];
                        if (content_length_str != null && long.TryParse(content_length_str, out var content_length))
                        {
                            // Read request content.
                            var buffer = new byte[client.ReceiveBufferSize];
                            while (content_length > 0)
                            {
                                var bytes_read = stream.Read(buffer, 0, buffer.Length);
                                if (bytes_read == 0)
                                    break;

                                content_length -= bytes_read;
                            }
                        }

                        var uri = new Uri(String.Format("http://{0}:{1}{2}", IPAddress.Loopback, ((IPEndPoint)LocalEndpoint).Port, request_line[1]));
                        if (uri.AbsolutePath.ToLowerInvariant() == "/callback")
                        {
                            OnHttpCallback(client, new HttpCallbackEventArgs(uri));

                            // Redirect agent to the finished page. This clears the explicit OAuth callback URI from agent location, and prevents page refreshes to reload /callback with stale data.
                            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                                writer.Write(String.Format("HTTP/1.0 301 Moved Permanently\r\nLocation: http://{0}:{1}/finished\r\n\r\n", IPAddress.Loopback, ((IPEndPoint)LocalEndpoint).Port));
                        }
                        else
                        {
                            var e = new HttpRequestEventArgs(uri);
                            OnHttpRequest(client, e);
                            using (e.Content)
                            {
                                // Send content.
                                var response_headers = Encoding.ASCII.GetBytes(String.Format("HTTP/1.0 200 OK\r\nContent-Type: {0}\r\nContent-Length: {1}\r\n\r\n",
                                    e.Type ?? "application/octet-stream",
                                    e.Content.Length));
                                stream.Write(response_headers, 0, response_headers.Length);
                                e.Content.CopyTo(stream);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Send response to the agent.
                        var status_code = ex is HttpException ex_http ? ex_http.GetHttpCode() : 500;
                        using (var resource_stream = _assembly.GetManifestResourceStream("eduOAuth.Resources.Html.error.html"))
                        using (var reader = new StreamReader(resource_stream, true))
                        {
                            string response;
                            try
                            {
                                response = String.Format(reader.ReadToEnd(),
                                    Thread.CurrentThread.CurrentUICulture.Name,
                                    HttpUtility.HtmlEncode(Resources.Strings.HtmlErrorTitle),
                                    HttpUtility.HtmlEncode(ex.Message),
                                    HttpUtility.HtmlEncode(Resources.Strings.HtmlErrorDescription),
                                    HttpUtility.HtmlEncode(Resources.Strings.HtmlErrorDetails),
                                    HttpUtility.HtmlEncode(ex.ToString()));
                            }
                            catch { response = HttpUtility.HtmlEncode(ex.ToString()); }
                            try
                            {
                                using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                                    writer.Write(String.Format("HTTP/1.0 {0} Error\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {1}\r\n\r\n{2}", status_code, response.Length, response));
                            }
                            catch { }
                        }
                    }
            }
            catch { }
        }

        /// <summary>
        /// Raises <see cref="HttpCallback"/> event
        /// </summary>
        /// <param name="sender">Event sender - a <see cref="TcpClient"/> object representing agent client</param>
        /// <param name="e">Event parameters</param>
        protected virtual void OnHttpCallback(object sender, HttpCallbackEventArgs e)
        {
            HttpCallback?.Invoke(sender, e);
        }

        /// <summary>
        /// Occurs when OAuth callback received.
        /// </summary>
        /// <remarks>Sender is the TCP client <see cref="TcpClient"/>.</remarks>
        public event EventHandler<HttpCallbackEventArgs> HttpCallback;

        /// <summary>
        /// Raises <see cref="HttpRequest"/> event
        /// </summary>
        /// <param name="sender">Event sender - a <see cref="TcpClient"/> object representing agent client</param>
        /// <param name="e">Event parameters</param>
        [SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "Stream tolerates multiple disposes.")]
        protected virtual void OnHttpRequest(object sender, HttpRequestEventArgs e)
        {
            HttpRequest?.Invoke(sender, e);
            if (e.Content != null)
                return;

            // The event handlers provided no data. Fall-back to default.
            switch (e.Uri.AbsolutePath.ToLowerInvariant())
            {
                case "/finished":
                    // Return response.
                    using (var resource_stream = _assembly.GetManifestResourceStream("eduOAuth.Resources.Html.finished.html"))
                    using (var reader = new StreamReader(resource_stream, true))
                    {
                        e.Type = "text/html; charset=UTF-8";
                        e.Content = new MemoryStream(Encoding.UTF8.GetBytes(
                            String.Format(reader.ReadToEnd(),
                                Thread.CurrentThread.CurrentUICulture.Name,
                                HttpUtility.HtmlEncode(Resources.Strings.HtmlFinishedTitle),
                                HttpUtility.HtmlEncode(Resources.Strings.HtmlFinishedDescription))));
                    }
                    return;

                case "/script.js":
                case "/style.css":
                    // Return static content.
                    e.Type = _mime_types[Path.GetExtension(e.Uri.LocalPath)];
                    e.Content = _assembly.GetManifestResourceStream("eduOAuth.Resources.Html" + e.Uri.AbsolutePath.Replace('/', '.'));
                    return;
            }

            throw new HttpException(404, String.Format(Resources.Strings.ErrorHttp404, e.Uri.AbsolutePath));
        }

        /// <summary>
        /// Occurs when browser requests data.
        /// </summary>
        /// <remarks>Sender is the TCP client <see cref="TcpClient"/>.</remarks>
        public event EventHandler<HttpRequestEventArgs> HttpRequest;

        #endregion
    }
}
