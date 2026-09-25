using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace HarAnalyzerV2
{
    public static class SazToHarConverter
    {
        private const long MaxExpandedSize =
            512L * 1024L * 1024L;

        // ============================================================
        // MAIN CONVERSION
        // ============================================================

        public static int Convert(
            string sazFile,
            string harFile)
        {
            if (string.IsNullOrWhiteSpace(sazFile))
                throw new ArgumentException(
                    "No SAZ file was specified.",
                    nameof(sazFile));

            if (!File.Exists(sazFile))
                throw new FileNotFoundException(
                    "The SAZ file was not found.",
                    sazFile);

            if (string.IsNullOrWhiteSpace(harFile))
                throw new ArgumentException(
                    "No HAR output file was specified.",
                    nameof(harFile));

            using ZipArchive archive =
                ZipFile.OpenRead(sazFile);

            // --------------------------------------------------------
            // Safety check
            // --------------------------------------------------------

            long expandedSize = 0;

            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                expandedSize += entry.Length;

                if (expandedSize > MaxExpandedSize)
                {
                    throw new InvalidDataException(
                        "The expanded SAZ archive exceeds " +
                        "the supported maximum size of 512 MB.");
                }
            }

            // --------------------------------------------------------
            // Find Fiddler session files
            //
            // raw/1_c.txt = client request
            // raw/1_s.txt = server response
            // raw/1_m.xml = Fiddler metadata
            // --------------------------------------------------------

            Dictionary<int, SessionFiles> sessions =
                new();

            Regex sessionRegex =
                new(
                    @"^raw/(?<id>\d+)_(?<type>[cms])\.(?<ext>txt|xml)$",
                    RegexOptions.IgnoreCase |
                    RegexOptions.Compiled);

            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                string entryName =
                    entry.FullName.Replace('\\', '/');

                Match match =
                    sessionRegex.Match(entryName);

                if (!match.Success)
                    continue;

                if (!int.TryParse(
                        match.Groups["id"].Value,
                        NumberStyles.Integer,
                        CultureInfo.InvariantCulture,
                        out int sessionId))
                {
                    continue;
                }

                if (!sessions.TryGetValue(
                        sessionId,
                        out SessionFiles? session))
                {
                    session =
                        new SessionFiles(sessionId);

                    sessions[sessionId] =
                        session;
                }

                string type =
                    match.Groups["type"]
                         .Value
                         .ToLowerInvariant();

                switch (type)
                {
                    case "c":
                        session.Client = entry;
                        break;

                    case "s":
                        session.Server = entry;
                        break;

                    case "m":
                        session.Metadata = entry;
                        break;
                }
            }

            if (sessions.Count == 0)
            {
                throw new InvalidDataException(
                    "No Fiddler sessions were found in the SAZ file.\n\n" +
                    "Expected files such as:\n" +
                    "raw/1_c.txt\n" +
                    "raw/1_s.txt\n" +
                    "raw/1_m.xml");
            }

            // --------------------------------------------------------
            // Convert sessions
            // --------------------------------------------------------

            List<object> harEntries =
                new();

            foreach (
                SessionFiles session
                in sessions.Values.OrderBy(x => x.Id))
            {
                // A session without a client request isn't useful.
                if (session.Client == null)
                    continue;

                byte[] clientBytes =
                    ReadBytes(session.Client);

                byte[] serverBytes =
                    session.Server != null
                        ? ReadBytes(session.Server)
                        : Array.Empty<byte>();

                string metadataXml =
                    session.Metadata != null
                        ? ReadText(session.Metadata)
                        : "";

                ParsedMessage request =
                    ParseMessage(clientBytes);

                ParsedMessage response =
                    ParseMessage(serverBytes);

                object harEntry =
                    CreateHarEntry(
                        request,
                        response,
                        metadataXml);

                harEntries.Add(harEntry);
            }

            if (harEntries.Count == 0)
            {
                throw new InvalidDataException(
                    "The SAZ archive was opened, but no usable " +
                    "HTTP sessions could be converted.");
            }

            // --------------------------------------------------------
            // HAR 1.2 root
            // --------------------------------------------------------

            var har = new
            {
                log = new
                {
                    version = "1.2",

                    creator = new
                    {
                        name =
                            "HAR Analyzer V2 - SAZ Converter",

                        version =
                            "2.0"
                    },

                    entries =
                        harEntries
                }
            };

            JsonSerializerOptions options =
                new()
                {
                    WriteIndented = true
                };

            string json =
                JsonSerializer.Serialize(
                    har,
                    options);

            File.WriteAllText(
                harFile,
                json,
                new UTF8Encoding(false));

            return harEntries.Count;
        }

        // ============================================================
        // CREATE HAR ENTRY
        // ============================================================

        private static object CreateHarEntry(
            ParsedMessage request,
            ParsedMessage response,
            string metadataXml)
        {
            // --------------------------------------------------------
            // Request line
            // --------------------------------------------------------

            string[] requestParts =
                request.FirstLine.Split(
                    ' ',
                    3,
                    StringSplitOptions.RemoveEmptyEntries);

            string method =
                requestParts.Length > 0
                    ? requestParts[0]
                    : "GET";

            string requestTarget =
                requestParts.Length > 1
                    ? requestParts[1]
                    : "/";

            string requestVersion =
                requestParts.Length > 2
                    ? requestParts[2]
                    : "HTTP/1.1";

            string url =
                BuildUrl(
                    requestTarget,
                    request.Headers);

            // --------------------------------------------------------
            // Response line
            // --------------------------------------------------------

            string[] responseParts =
                response.FirstLine.Split(
                    ' ',
                    3,
                    StringSplitOptions.RemoveEmptyEntries);

            string responseVersion =
                responseParts.Length > 0
                    ? responseParts[0]
                    : "HTTP/1.1";

            int status = 0;

            if (responseParts.Length > 1)
            {
                int.TryParse(
                    responseParts[1],
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out status);
            }

            string statusText =
                responseParts.Length > 2
                    ? responseParts[2]
                    : "";

            // --------------------------------------------------------
            // Content types
            // --------------------------------------------------------

            string requestContentType =
                Header(
                    request.Headers,
                    "Content-Type");

            string responseContentType =
                Header(
                    response.Headers,
                    "Content-Type");

            // --------------------------------------------------------
            // Response decompression
            // --------------------------------------------------------

            byte[] responseBody =
                DecompressBody(
                    response.Body,
                    Header(
                        response.Headers,
                        "Content-Encoding"));

            // --------------------------------------------------------
            // Fiddler metadata
            // --------------------------------------------------------

            Dictionary<string, string> metadata =
                ParseMetadata(metadataXml);

            DateTimeOffset startTime =
                GetDate(
                    metadata,
                    "ClientConnected")
                ??
                GetDate(
                    metadata,
                    "ClientBeginRequest")
                ??
                GetDate(
                    metadata,
                    "FiddlerBeginRequest")
                ??
                DateTimeOffset.UtcNow;

            // --------------------------------------------------------
            // Timings
            // --------------------------------------------------------

            HarTimings timings =
                CalculateTimings(metadata);

            // --------------------------------------------------------
            // Request
            // --------------------------------------------------------

            Dictionary<string, object?> harRequest =
                new()
                {
                    ["method"] =
                        method,

                    ["url"] =
                        url,

                    ["httpVersion"] =
                        requestVersion,

                    ["cookies"] =
                        ParseRequestCookies(
                            Header(
                                request.Headers,
                                "Cookie")),

                    ["headers"] =
                        ConvertHeaders(
                            request.Headers),

                    ["queryString"] =
                        ParseQueryString(url),

                    ["headersSize"] =
                        request.HeaderSize,

                    ["bodySize"] =
                        request.Body.LongLength
                };

            // --------------------------------------------------------
            // Request body
            // --------------------------------------------------------

            if (request.Body.Length > 0)
            {
                bool requestIsText =
                    IsTextContent(
                        requestContentType,
                        request.Body);

                Dictionary<string, object?> postData =
                    new()
                    {
                        ["mimeType"] =
                            string.IsNullOrWhiteSpace(
                                requestContentType)
                                ? "application/octet-stream"
                                : requestContentType,

                        ["text"] =
                            requestIsText
                                ? DecodeText(
                                    request.Body,
                                    requestContentType)
                                : System.Convert.ToBase64String(
                                    request.Body)
                    };

                if (!requestIsText)
                {
                    postData["encoding"] =
                        "base64";
                }

                harRequest["postData"] =
                    postData;
            }

            // --------------------------------------------------------
            // Response content
            // --------------------------------------------------------

            bool responseIsText =
                IsTextContent(
                    responseContentType,
                    responseBody);

            Dictionary<string, object?> content =
                new()
                {
                    ["size"] =
                        responseBody.LongLength,

                    ["mimeType"] =
                        string.IsNullOrWhiteSpace(
                            responseContentType)
                            ? "application/octet-stream"
                            : responseContentType
                };

            if (responseBody.Length > 0)
            {
                if (responseIsText)
                {
                    content["text"] =
                        DecodeText(
                            responseBody,
                            responseContentType);
                }
                else
                {
                    content["text"] =
                        System.Convert.ToBase64String(
                            responseBody);

                    content["encoding"] =
                        "base64";
                }
            }

            // --------------------------------------------------------
            // Response
            // --------------------------------------------------------

            Dictionary<string, object?> harResponse =
                new()
                {
                    ["status"] =
                        status,

                    ["statusText"] =
                        statusText,

                    ["httpVersion"] =
                        responseVersion,

                    ["cookies"] =
                        ParseResponseCookies(
                            response.Headers),

                    ["headers"] =
                        ConvertHeaders(
                            response.Headers),

                    ["content"] =
                        content,

                    ["redirectURL"] =
                        Header(
                            response.Headers,
                            "Location"),

                    ["headersSize"] =
                        response.HeaderSize,

                    // HAR bodySize represents encoded/captured
                    // message body size.
                    ["bodySize"] =
                        response.Body.LongLength
                };

            // --------------------------------------------------------
            // HAR entry
            // --------------------------------------------------------

            Dictionary<string, object?> entry =
                new()
                {
                    ["startedDateTime"] =
                        startTime
                            .ToUniversalTime()
                            .ToString(
                                "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                                CultureInfo.InvariantCulture),

                    ["time"] =
                        timings.Total,

                    ["request"] =
                        harRequest,

                    ["response"] =
                        harResponse,

                    ["cache"] =
                        new Dictionary<string, object>(),

                    ["timings"] =
                        new Dictionary<string, object>
                        {
                            ["blocked"] =
                                timings.Blocked,

                            ["dns"] =
                                timings.Dns,

                            ["connect"] =
                                timings.Connect,

                            ["send"] =
                                timings.Send,

                            ["wait"] =
                                timings.Wait,

                            ["receive"] =
                                timings.Receive,

                            ["ssl"] =
                                timings.Ssl
                        }
                };

            // --------------------------------------------------------
            // Server IP
            // --------------------------------------------------------

            string serverIp =
                FirstNonEmpty(
                    MetadataValue(
                        metadata,
                        "x-hostip"),

                    MetadataValue(
                        metadata,
                        "x-serverip"),

                    MetadataValue(
                        metadata,
                        "ServerIP"));

            if (!string.IsNullOrWhiteSpace(
                    serverIp))
            {
                entry["serverIPAddress"] =
                    serverIp;
            }

            return entry;
        }

        // ============================================================
        // PARSE RAW HTTP MESSAGE
        // ============================================================

        private static ParsedMessage ParseMessage(
            byte[] data)
        {
            ParsedMessage result =
                new();

            if (data.Length == 0)
                return result;

            int separator =
                FindHeaderSeparator(
                    data,
                    out int separatorLength);

            byte[] headerBytes;

            if (separator >= 0)
            {
                headerBytes =
                    data[..separator];

                result.Body =
                    data[
                        (separator + separatorLength)..];

                result.HeaderSize =
                    separator +
                    separatorLength;
            }
            else
            {
                headerBytes =
                    data;

                result.Body =
                    Array.Empty<byte>();

                result.HeaderSize =
                    data.Length;
            }

            // HTTP headers are byte-oriented.
            string headerText =
                Encoding.Latin1.GetString(
                    headerBytes);

            string[] lines =
                headerText
                    .Replace(
                        "\r\n",
                        "\n")
                    .Replace(
                        '\r',
                        '\n')
                    .Split('\n');

            if (lines.Length > 0)
            {
                result.FirstLine =
                    lines[0];
            }

            string? currentHeaderName =
                null;

            StringBuilder? currentHeaderValue =
                null;

            void FlushHeader()
            {
                if (currentHeaderName == null)
                    return;

                result.Headers.Add(
                    new HeaderPair
                    {
                        Name =
                            currentHeaderName,

                        Value =
                            currentHeaderValue?.ToString()
                            ?? ""
                    });

                currentHeaderName =
                    null;

                currentHeaderValue =
                    null;
            }

            for (
                int i = 1;
                i < lines.Length;
                i++)
            {
                string line =
                    lines[i];

                // Old-style folded HTTP header.
                if (
                    (line.StartsWith(" ") ||
                     line.StartsWith("\t")) &&
                    currentHeaderName != null)
                {
                    currentHeaderValue!
                        .Append(' ')
                        .Append(
                            line.Trim());

                    continue;
                }

                FlushHeader();

                int colon =
                    line.IndexOf(':');

                if (colon <= 0)
                    continue;

                currentHeaderName =
                    line[..colon].Trim();

                currentHeaderValue =
                    new StringBuilder(
                        line[(colon + 1)..]
                            .Trim());
            }

            FlushHeader();

            return result;
        }

        // ============================================================
        // FIND HTTP HEADER/BODY SEPARATOR
        // ============================================================

        private static int FindHeaderSeparator(
            byte[] data,
            out int separatorLength)
        {
            // CRLF CRLF

            for (
                int i = 0;
                i <= data.Length - 4;
                i++)
            {
                if (
                    data[i] == 13 &&
                    data[i + 1] == 10 &&
                    data[i + 2] == 13 &&
                    data[i + 3] == 10)
                {
                    separatorLength = 4;

                    return i;
                }
            }

            // LF LF fallback

            for (
                int i = 0;
                i <= data.Length - 2;
                i++)
            {
                if (
                    data[i] == 10 &&
                    data[i + 1] == 10)
                {
                    separatorLength = 2;

                    return i;
                }
            }

            separatorLength = 0;

            return -1;
        }

        // ============================================================
        // BUILD URL
        // ============================================================

        private static string BuildUrl(
            string target,
            List<HeaderPair> headers)
        {
            if (Uri.TryCreate(
                    target,
                    UriKind.Absolute,
                    out Uri? absoluteUri))
            {
                return absoluteUri.ToString();
            }

            string host =
                Header(
                    headers,
                    "Host");

            if (string.IsNullOrWhiteSpace(
                    host))
            {
                return target;
            }

            string scheme =
                "http";

            string forwardedProto =
                Header(
                    headers,
                    "X-Forwarded-Proto");

            if (forwardedProto.Equals(
                    "https",
                    StringComparison.OrdinalIgnoreCase))
            {
                scheme = "https";
            }
            else if (
                host.EndsWith(
                    ":443",
                    StringComparison.OrdinalIgnoreCase))
            {
                scheme = "https";
            }

            if (!target.StartsWith('/'))
            {
                target =
                    "/" + target;
            }

            return
                $"{scheme}://{host}{target}";
        }

        // ============================================================
        // PARSE FIDDLER METADATA
        // ============================================================

        private static Dictionary<string, string>
            ParseMetadata(
                string xml)
        {
            Dictionary<string, string> result =
                new(
                    StringComparer.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(
                    xml))
            {
                return result;
            }

            try
            {
                XDocument document =
                    XDocument.Parse(
                        xml,
                        LoadOptions.PreserveWhitespace);

                XElement? timers =
                    document
                        .Descendants()
                        .FirstOrDefault(
                            x =>
                                x.Name.LocalName.Equals(
                                    "SessionTimers",
                                    StringComparison.OrdinalIgnoreCase));

                if (timers != null)
                {
                    foreach (
                        XAttribute attribute
                        in timers.Attributes())
                    {
                        result[
                            attribute.Name.LocalName] =
                            attribute.Value;
                    }
                }

                foreach (
                    XElement flag
                    in document
                        .Descendants()
                        .Where(
                            x =>
                                x.Name.LocalName.Equals(
                                    "SessionFlag",
                                    StringComparison.OrdinalIgnoreCase)))
                {
                    string name =
                        flag.Attribute("N")
                            ?.Value ?? "";

                    string value =
                        flag.Attribute("V")
                            ?.Value ?? "";

                    if (!string.IsNullOrWhiteSpace(
                            name))
                    {
                        result[name] =
                            value;
                    }
                }
            }
            catch
            {
                // Metadata is useful but not mandatory.
                // A damaged metadata XML file should not prevent
                // the HTTP request/response from being converted.
            }

            return result;
        }

        // ============================================================
        // FIDDLER TIMINGS
        // ============================================================

        private static HarTimings CalculateTimings(
            Dictionary<string, string> metadata)
        {
            DateTimeOffset? clientConnected =
                GetDate(
                    metadata,
                    "ClientConnected");

            DateTimeOffset? clientBeginRequest =
                GetDate(
                    metadata,
                    "ClientBeginRequest");

            DateTimeOffset? clientDoneRequest =
                GetDate(
                    metadata,
                    "ClientDoneRequest");

            DateTimeOffset? fiddlerBeginRequest =
                GetDate(
                    metadata,
                    "FiddlerBeginRequest");

            DateTimeOffset? serverGotRequest =
                GetDate(
                    metadata,
                    "ServerGotRequest");

            DateTimeOffset? serverBeginResponse =
                GetDate(
                    metadata,
                    "ServerBeginResponse");

            DateTimeOffset? gotResponseHeaders =
                GetDate(
                    metadata,
                    "GotResponseHeaders");

            DateTimeOffset? serverDoneResponse =
                GetDate(
                    metadata,
                    "ServerDoneResponse");

            DateTimeOffset? clientBeginResponse =
                GetDate(
                    metadata,
                    "ClientBeginResponse");

            DateTimeOffset? clientDoneResponse =
                GetDate(
                    metadata,
                    "ClientDoneResponse");

            DateTimeOffset? dnsStart =
                GetDate(
                    metadata,
                    "DNSTime");

            DateTimeOffset? serverConnected =
                GetDate(
                    metadata,
                    "ServerConnected");

            // --------------------------------------------------------
            // Blocked
            // --------------------------------------------------------

            double blocked =
                Duration(
                    clientConnected,
                    clientBeginRequest);

            // --------------------------------------------------------
            // DNS
            //
            // Fiddler metadata differs somewhat between versions.
            // Use -1 when the timing is unavailable.
            // --------------------------------------------------------

            double dns = -1;

            if (dnsStart != null &&
                serverConnected != null)
            {
                double candidate =
                    Duration(
                        dnsStart,
                        serverConnected);

                if (candidate > 0)
                    dns = candidate;
            }

            // --------------------------------------------------------
            // Connect
            // --------------------------------------------------------

            double connect = -1;

            if (serverConnected != null &&
                fiddlerBeginRequest != null)
            {
                double candidate =
                    Duration(
                        serverConnected,
                        fiddlerBeginRequest);

                if (candidate > 0)
                    connect = candidate;
            }

            // --------------------------------------------------------
            // Send
            // --------------------------------------------------------

            double send =
                Duration(
                    fiddlerBeginRequest
                    ?? clientBeginRequest,

                    serverGotRequest
                    ?? clientDoneRequest);

            // --------------------------------------------------------
            // Wait
            // --------------------------------------------------------

            double wait =
                Duration(
                    serverGotRequest
                    ?? clientDoneRequest,

                    serverBeginResponse
                    ?? gotResponseHeaders);

            // --------------------------------------------------------
            // Receive
            // --------------------------------------------------------

            double receive =
                Duration(
                    clientBeginResponse
                    ?? gotResponseHeaders
                    ?? serverBeginResponse,

                    clientDoneResponse
                    ?? serverDoneResponse);

            // --------------------------------------------------------
            // SSL
            //
            // Not all SAZ metadata contains enough information to
            // derive SSL negotiation separately.
            // --------------------------------------------------------

            double ssl = -1;

            // --------------------------------------------------------
            // Total
            // --------------------------------------------------------

            DateTimeOffset? totalStart =
                clientBeginRequest
                ?? clientConnected
                ?? fiddlerBeginRequest;

            DateTimeOffset? totalEnd =
                clientDoneResponse
                ?? serverDoneResponse
                ?? serverBeginResponse;

            double total =
                Duration(
                    totalStart,
                    totalEnd);

            if (total <= 0)
            {
                total = 0;

                if (blocked > 0)
                    total += blocked;

                if (dns > 0)
                    total += dns;

                if (connect > 0)
                    total += connect;

                if (send > 0)
                    total += send;

                if (wait > 0)
                    total += wait;

                if (receive > 0)
                    total += receive;
            }

            return new HarTimings
            {
                Blocked =
                    RoundTiming(blocked),

                Dns =
                    dns < 0
                        ? -1
                        : RoundTiming(dns),

                Connect =
                    connect < 0
                        ? -1
                        : RoundTiming(connect),

                Send =
                    RoundTiming(send),

                Wait =
                    RoundTiming(wait),

                Receive =
                    RoundTiming(receive),

                Ssl =
                    ssl,

                Total =
                    RoundTiming(total)
            };
        }

        private static double Duration(
            DateTimeOffset? start,
            DateTimeOffset? end)
        {
            if (start == null ||
                end == null)
            {
                return 0;
            }

            double milliseconds =
                (end.Value - start.Value)
                    .TotalMilliseconds;

            if (milliseconds < 0)
                return 0;

            return milliseconds;
        }

        private static double RoundTiming(
            double value)
        {
            return Math.Round(
                Math.Max(0, value),
                3);
        }

        // ============================================================
        // DATE PARSING
        // ============================================================

        private static DateTimeOffset? GetDate(
            Dictionary<string, string> metadata,
            string key)
        {
            string value =
                MetadataValue(
                    metadata,
                    key);

            if (string.IsNullOrWhiteSpace(
                    value))
            {
                return null;
            }

            if (DateTimeOffset.TryParse(
                    value,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AllowWhiteSpaces |
                    DateTimeStyles.AssumeLocal,
                    out DateTimeOffset result))
            {
                return result;
            }

            string[] formats =
            {
                "yyyy-MM-ddTHH:mm:ss.fffffffK",
                "yyyy-MM-ddTHH:mm:ss.ffffffK",
                "yyyy-MM-ddTHH:mm:ss.fffffK",
                "yyyy-MM-ddTHH:mm:ss.ffffK",
                "yyyy-MM-ddTHH:mm:ss.fffK",
                "yyyy-MM-ddTHH:mm:ssK",

                "yyyy-MM-dd HH:mm:ss.fffffff",
                "yyyy-MM-dd HH:mm:ss.fff",
                "yyyy-MM-dd HH:mm:ss"
            };

            if (DateTimeOffset.TryParseExact(
                    value,
                    formats,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AllowWhiteSpaces |
                    DateTimeStyles.AssumeLocal,
                    out result))
            {
                return result;
            }

            return null;
        }

        // ============================================================
        // RESPONSE BODY DECOMPRESSION
        // ============================================================

        private static byte[] DecompressBody(
            byte[] body,
            string contentEncoding)
        {
            if (body.Length == 0)
                return body;

            if (string.IsNullOrWhiteSpace(
                    contentEncoding))
            {
                return body;
            }

            // There may technically be multiple encodings.
            // The common Fiddler cases are gzip, deflate and br.

            string encoding =
                contentEncoding
                    .Split(',')
                    .Last()
                    .Trim()
                    .ToLowerInvariant();

            try
            {
                using MemoryStream input =
                    new(body);

                using MemoryStream output =
                    new();

                Stream? decoder =
                    encoding switch
                    {
                        "gzip" =>
                            new GZipStream(
                                input,
                                CompressionMode.Decompress),

                        "deflate" =>
                            new DeflateStream(
                                input,
                                CompressionMode.Decompress),

                        "br" =>
                            new BrotliStream(
                                input,
                                CompressionMode.Decompress),

                        _ =>
                            null
                    };

                if (decoder == null)
                    return body;

                using (decoder)
                {
                    decoder.CopyTo(output);
                }

                return output.ToArray();
            }
            catch
            {
                // If Fiddler stored the body already decoded,
                // or if the content encoding is inconsistent,
                // preserve the captured body rather than failing
                // the entire SAZ conversion.
                return body;
            }
        }

        // ============================================================
        // TEXT / BINARY DETECTION
        // ============================================================

        private static bool IsTextContent(
            string contentType,
            byte[] body)
        {
            string mime =
                contentType
                    .ToLowerInvariant();

            if (
                mime.StartsWith("text/") ||
                mime.Contains("json") ||
                mime.Contains("xml") ||
                mime.Contains("javascript") ||
                mime.Contains("ecmascript") ||
                mime.Contains("x-www-form-urlencoded") ||
                mime.Contains("graphql") ||
                mime.Contains("svg") ||
                mime.Contains("html") ||
                mime.Contains("css"))
            {
                return true;
            }

            if (body.Length == 0)
                return true;

            int sampleSize =
                Math.Min(
                    body.Length,
                    4096);

            int suspiciousBytes = 0;

            for (
                int i = 0;
                i < sampleSize;
                i++)
            {
                byte value =
                    body[i];

                // NULL is a strong binary indicator.
                if (value == 0)
                    return false;

                if (
                    value < 9 ||
                    (value > 13 &&
                     value < 32))
                {
                    suspiciousBytes++;
                }
            }

            return
                suspiciousBytes <
                sampleSize * 0.05;
        }

        // ============================================================
        // TEXT DECODING
        // ============================================================

        private static string DecodeText(
            byte[] body,
            string contentType)
        {
            Encoding encoding =
                Encoding.UTF8;

            Match charsetMatch =
                Regex.Match(
                    contentType ?? "",
                    @"charset\s*=\s*[""']?(?<charset>[^;""'\s]+)",
                    RegexOptions.IgnoreCase);

            if (charsetMatch.Success)
            {
                string charset =
                    charsetMatch
                        .Groups["charset"]
                        .Value;

                try
                {
                    Encoding.RegisterProvider(
                        CodePagesEncodingProvider.Instance);

                    encoding =
                        Encoding.GetEncoding(
                            charset);
                }
                catch
                {
                    encoding =
                        Encoding.UTF8;
                }
            }

            try
            {
                return encoding.GetString(
                    body);
            }
            catch
            {
                return Encoding.UTF8.GetString(
                    body);
            }
        }

        // ============================================================
        // HAR HEADERS
        // ============================================================

        private static List<object> ConvertHeaders(
            List<HeaderPair> headers)
        {
            List<object> result =
                new();

            foreach (HeaderPair header in headers)
            {
                result.Add(
                    new Dictionary<string, string>
                    {
                        ["name"] =
                            header.Name,

                        ["value"] =
                            header.Value
                    });
            }

            return result;
        }

        private static string Header(
            List<HeaderPair> headers,
            string name)
        {
            HeaderPair? header =
                headers.FirstOrDefault(
                    h =>
                        h.Name.Equals(
                            name,
                            StringComparison.OrdinalIgnoreCase));

            return
                header?.Value ?? "";
        }

        // ============================================================
        // REQUEST COOKIES
        // ============================================================

        private static List<object> ParseRequestCookies(
            string cookieHeader)
        {
            List<object> result =
                new();

            if (string.IsNullOrWhiteSpace(
                    cookieHeader))
            {
                return result;
            }

            foreach (
                string part
                in cookieHeader.Split(';'))
            {
                int equals =
                    part.IndexOf('=');

                if (equals <= 0)
                    continue;

                string name =
                    part[..equals]
                        .Trim();

                string value =
                    part[(equals + 1)..]
                        .Trim();

                result.Add(
                    new Dictionary<string, object?>
                    {
                        ["name"] =
                            name,

                        ["value"] =
                            value
                    });
            }

            return result;
        }

        // ============================================================
        // RESPONSE COOKIES
        // ============================================================

        private static List<object> ParseResponseCookies(
            List<HeaderPair> headers)
        {
            List<object> result =
                new();

            IEnumerable<HeaderPair> setCookies =
                headers.Where(
                    h =>
                        h.Name.Equals(
                            "Set-Cookie",
                            StringComparison.OrdinalIgnoreCase));

            foreach (
                HeaderPair header
                in setCookies)
            {
                string[] parts =
                    header.Value.Split(';');

                if (parts.Length == 0)
                    continue;

                int equals =
                    parts[0].IndexOf('=');

                if (equals <= 0)
                    continue;

                Dictionary<string, object?> cookie =
                    new()
                    {
                        ["name"] =
                            parts[0][..equals]
                                .Trim(),

                        ["value"] =
                            parts[0][(equals + 1)..]
                                .Trim()
                    };

                for (
                    int i = 1;
                    i < parts.Length;
                    i++)
                {
                    string attribute =
                        parts[i].Trim();

                    int attributeEquals =
                        attribute.IndexOf('=');

                    string attributeName =
                        attributeEquals >= 0
                            ? attribute[..attributeEquals]
                                .Trim()
                            : attribute;

                    string attributeValue =
                        attributeEquals >= 0
                            ? attribute[(attributeEquals + 1)..]
                                .Trim()
                            : "";

                    switch (
                        attributeName.ToLowerInvariant())
                    {
                        case "path":

                            cookie["path"] =
                                attributeValue;

                            break;

                        case "domain":

                            cookie["domain"] =
                                attributeValue;

                            break;

                        case "expires":

                            if (DateTimeOffset.TryParse(
                                    attributeValue,
                                    CultureInfo.InvariantCulture,
                                    DateTimeStyles.AllowWhiteSpaces,
                                    out DateTimeOffset expires))
                            {
                                cookie["expires"] =
                                    expires
                                        .ToUniversalTime()
                                        .ToString(
                                            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                                            CultureInfo.InvariantCulture);
                            }

                            break;

                        case "httponly":

                            cookie["httpOnly"] =
                                true;

                            break;

                        case "secure":

                            cookie["secure"] =
                                true;

                            break;

                        case "samesite":

                            cookie["sameSite"] =
                                attributeValue;

                            break;
                    }
                }

                result.Add(cookie);
            }

            return result;
        }

        // ============================================================
        // QUERY STRING
        // ============================================================

        private static List<object> ParseQueryString(
            string url)
        {
            List<object> result =
                new();

            if (!Uri.TryCreate(
                    url,
                    UriKind.Absolute,
                    out Uri? uri))
            {
                return result;
            }

            string query =
                uri.Query;

            if (string.IsNullOrWhiteSpace(
                    query))
            {
                return result;
            }

            if (query.StartsWith('?'))
            {
                query =
                    query[1..];
            }

            foreach (
                string part
                in query.Split(
                    '&',
                    StringSplitOptions.RemoveEmptyEntries))
            {
                int equals =
                    part.IndexOf('=');

                string name =
                    equals >= 0
                        ? part[..equals]
                        : part;

                string value =
                    equals >= 0
                        ? part[(equals + 1)..]
                        : "";

                result.Add(
                    new Dictionary<string, string>
                    {
                        ["name"] =
                            UrlDecode(name),

                        ["value"] =
                            UrlDecode(value)
                    });
            }

            return result;
        }

        private static string UrlDecode(
            string value)
        {
            try
            {
                return
                    Uri.UnescapeDataString(
                        value.Replace(
                            "+",
                            " "));
            }
            catch
            {
                return value;
            }
        }

        // ============================================================
        // METADATA HELPERS
        // ============================================================

        private static string MetadataValue(
            Dictionary<string, string> metadata,
            string name)
        {
            if (metadata.TryGetValue(
                    name,
                    out string? value))
            {
                return value;
            }

            return "";
        }

        private static string FirstNonEmpty(
            params string[] values)
        {
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(
                        value))
                {
                    return value;
                }
            }

            return "";
        }

        // ============================================================
        // ZIP ENTRY HELPERS
        // ============================================================

        private static byte[] ReadBytes(
            ZipArchiveEntry entry)
        {
            using Stream input =
                entry.Open();

            using MemoryStream output =
                new();

            input.CopyTo(output);

            return output.ToArray();
        }

        private static string ReadText(
            ZipArchiveEntry entry)
        {
            using Stream input =
                entry.Open();

            using StreamReader reader =
                new(
                    input,
                    Encoding.UTF8,
                    true);

            return reader.ReadToEnd();
        }

        // ============================================================
        // INTERNAL TYPES
        // ============================================================

        private sealed class SessionFiles
        {
            public int Id { get; }

            public ZipArchiveEntry? Client
            {
                get;
                set;
            }

            public ZipArchiveEntry? Server
            {
                get;
                set;
            }

            public ZipArchiveEntry? Metadata
            {
                get;
                set;
            }

            public SessionFiles(
                int id)
            {
                Id = id;
            }
        }

        private sealed class ParsedMessage
        {
            public string FirstLine
            {
                get;
                set;
            } = "";

            public List<HeaderPair> Headers
            {
                get;
                set;
            } = new();

            public byte[] Body
            {
                get;
                set;
            } = Array.Empty<byte>();

            public int HeaderSize
            {
                get;
                set;
            }
        }

        private sealed class HeaderPair
        {
            public string Name
            {
                get;
                set;
            } = "";

            public string Value
            {
                get;
                set;
            } = "";
        }

        private sealed class HarTimings
        {
            public double Blocked
            {
                get;
                set;
            }

            public double Dns
            {
                get;
                set;
            }

            public double Connect
            {
                get;
                set;
            }

            public double Send
            {
                get;
                set;
            }

            public double Wait
            {
                get;
                set;
            }

            public double Receive
            {
                get;
                set;
            }

            public double Ssl
            {
                get;
                set;
            }

            public double Total
            {
                get;
                set;
            }
        }
    }
}