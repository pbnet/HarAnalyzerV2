using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace HarAnalyzerV2
{
    public partial class MainWindow : Window
    {
        private readonly List<HarItem> allItems = new();

        private string? currentHarFile;

        public MainWindow()
        {
            InitializeComponent();
        }

        // ============================================================
        // OPEN HAR
        // ============================================================

        private void OpenHar_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new()
            {
                Filter =
                    "HAR files (*.har)|*.har|" +
                    "All files (*.*)|*.*",

                Title = "Open HAR file"
            };

            if (dialog.ShowDialog() != true)
                return;

            LoadHarFile(dialog.FileName);
        }

        // ============================================================
        // LOAD HAR
        // ============================================================

        private void LoadHarFile(string fileName)
        {
            try
            {
                StatusText.Text = "Loading HAR...";

                string json =
                    File.ReadAllText(fileName);

                using JsonDocument document =
                    JsonDocument.Parse(json);

                if (!document.RootElement.TryGetProperty(
                        "log",
                        out JsonElement log))
                {
                    MessageBox.Show(
                        "Invalid HAR file.\n\n" +
                        "The 'log' section was not found.",
                        "HAR Analyzer",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);

                    StatusText.Text = "Invalid HAR file.";

                    return;
                }

                if (!log.TryGetProperty(
                        "entries",
                        out JsonElement entries))
                {
                    MessageBox.Show(
                        "Invalid HAR file.\n\n" +
                        "The 'entries' section was not found.",
                        "HAR Analyzer",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);

                    StatusText.Text = "Invalid HAR file.";

                    return;
                }

                if (entries.ValueKind !=
                    JsonValueKind.Array)
                {
                    MessageBox.Show(
                        "Invalid HAR file.\n\n" +
                        "'entries' is not an array.",
                        "HAR Analyzer",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);

                    StatusText.Text = "Invalid HAR file.";

                    return;
                }

                allItems.Clear();

                foreach (
                    JsonElement entry
                    in entries.EnumerateArray())
                {
                    if (!entry.TryGetProperty(
                            "request",
                            out JsonElement request))
                    {
                        continue;
                    }

                    if (!entry.TryGetProperty(
                            "response",
                            out JsonElement response))
                    {
                        continue;
                    }

                    string method =
                        GetStringProperty(
                            request,
                            "method");

                    string url =
                        GetStringProperty(
                            request,
                            "url");

                    int status =
                        GetIntProperty(
                            response,
                            "status");

                    double time =
                        GetDoubleProperty(
                            entry,
                            "time");

                    string host = "";

                    if (Uri.TryCreate(
                            url,
                            UriKind.Absolute,
                            out Uri? uri))
                    {
                        host = uri.Host;
                    }

                    HarItem item = new()
                    {
                        Method = method,
                        Status = status,
                        Host = host,
                        Url = url,
                        TimeValue = time,

                        // Clone is required because JsonDocument
                        // is disposed when this method exits.
                        Entry = entry.Clone()
                    };

                    allItems.Add(item);
                }

                currentHarFile = fileName;

                HarGrid.ItemsSource = null;
                HarGrid.ItemsSource = allItems;

                RequestText.Text = "";
                ResponseText.Text = "";
                BodyText.Text = "";

                Title =
                    "HAR Analyzer V2 - " +
                    Path.GetFileName(fileName);

                // ----------------------------------------------------
                // IMPORT COUNT
                // ----------------------------------------------------

                StatusText.Text =
                    $"Loaded {allItems.Count:N0} frames.";

                MessageBox.Show(
                    $"{allItems.Count:N0} frames were successfully " +
                    "imported from the HAR file.",
                    "HAR Import Complete",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (JsonException ex)
            {
                StatusText.Text =
                    "Invalid HAR file.";

                MessageBox.Show(
                    "The selected file does not contain " +
                    "valid HAR/JSON data.\n\n" +
                    ex.Message,
                    "Invalid HAR",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                StatusText.Text =
                    "Error loading HAR.";

                MessageBox.Show(
                    ex.ToString(),
                    "Error loading HAR",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        // ============================================================
        // SAZ -> HAR
        // ============================================================

        private async void ConvertSaz_Click(
            object sender,
            RoutedEventArgs e)
        {
            OpenFileDialog openDialog = new()
            {
                Filter =
                    "Fiddler SAZ files (*.saz)|*.saz|" +
                    "All files (*.*)|*.*",

                Title =
                    "Select Fiddler SAZ file"
            };

            if (openDialog.ShowDialog() != true)
                return;

            string suggestedName =
                Path.GetFileNameWithoutExtension(
                    openDialog.FileName)
                + ".har";

            SaveFileDialog saveDialog = new()
            {
                Filter =
                    "HAR files (*.har)|*.har",

                Title =
                    "Save converted HAR file",

                FileName =
                    suggestedName,

                DefaultExt =
                    ".har",

                AddExtension =
                    true,

                InitialDirectory =
                    Path.GetDirectoryName(
                        openDialog.FileName)
            };

            if (saveDialog.ShowDialog() != true)
                return;

            try
            {
                StatusText.Text =
                    "Converting SAZ to HAR...";

                Mouse.OverrideCursor =
                    Cursors.Wait;

                IsEnabled = false;

                int sessionCount =
                    await Task.Run(
                        () =>
                            SazToHarConverter.Convert(
                                openDialog.FileName,
                                saveDialog.FileName));

                StatusText.Text =
                    $"Converted {sessionCount:N0} sessions.";

                MessageBoxResult result =
                    MessageBox.Show(
                        "SAZ conversion completed successfully!\n\n" +

                        $"Sessions converted: {sessionCount:N0}\n\n" +

                        "HAR file:\n" +
                        saveDialog.FileName +
                        "\n\n" +

                        "Do you want to load the generated HAR now?",

                        "SAZ → HAR",

                        MessageBoxButton.YesNo,
                        MessageBoxImage.Information);

                if (result ==
                    MessageBoxResult.Yes)
                {
                    LoadHarFile(
                        saveDialog.FileName);
                }
            }
            catch (InvalidDataException ex)
            {
                StatusText.Text =
                    "SAZ conversion failed.";

                MessageBox.Show(
                    ex.Message,
                    "Invalid SAZ file",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                StatusText.Text =
                    "SAZ conversion failed.";

                MessageBox.Show(
                    ex.ToString(),
                    "SAZ → HAR Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            finally
            {
                IsEnabled = true;

                Mouse.OverrideCursor =
                    null;
            }
        }

        // ============================================================
        // ZIP HAR
        // ============================================================

        private void ZipHar_Click(
            object sender,
            RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(
                    currentHarFile) ||
                !File.Exists(currentHarFile))
            {
                MessageBox.Show(
                    "Please open a HAR file first.",
                    "HAR Analyzer",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                return;
            }

            try
            {
                string? directory =
                    Path.GetDirectoryName(
                        currentHarFile);

                if (string.IsNullOrWhiteSpace(
                        directory))
                {
                    directory =
                        Environment.CurrentDirectory;
                }

                string name =
                    Path.GetFileNameWithoutExtension(
                        currentHarFile);

                string zipFile =
                    Path.Combine(
                        directory,
                        name + ".zip");

                if (File.Exists(zipFile))
                {
                    MessageBoxResult result =
                        MessageBox.Show(
                            "The ZIP file already exists:\n\n" +
                            zipFile +
                            "\n\n" +
                            "Do you want to replace it?",

                            "HAR Analyzer",

                            MessageBoxButton.YesNo,
                            MessageBoxImage.Question);

                    if (result !=
                        MessageBoxResult.Yes)
                    {
                        return;
                    }

                    File.Delete(zipFile);
                }

                using (
                    ZipArchive archive =
                        ZipFile.Open(
                            zipFile,
                            ZipArchiveMode.Create))
                {
                    archive.CreateEntryFromFile(
                        currentHarFile,
                        Path.GetFileName(
                            currentHarFile),
                        CompressionLevel.Optimal);
                }

                FileInfo original =
                    new(currentHarFile);

                FileInfo compressed =
                    new(zipFile);

                double reduction = 0;

                if (original.Length > 0)
                {
                    reduction =
                        100.0 -
                        (
                            (double)compressed.Length /
                            original.Length *
                            100.0
                        );
                }

                StatusText.Text =
                    "HAR compressed successfully.";

                MessageBox.Show(
                    "HAR file compressed successfully!\n\n" +

                    $"Original size: " +
                    $"{FormatBytes(original.Length)}\n" +

                    $"ZIP size: " +
                    $"{FormatBytes(compressed.Length)}\n" +

                    $"Reduction: " +
                    $"{reduction:0.0}%\n\n" +

                    "Saved to:\n" +
                    zipFile,

                    "HAR Analyzer",

                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                StatusText.Text =
                    "ZIP operation failed.";

                MessageBox.Show(
                    ex.ToString(),
                    "ZIP Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        // ============================================================
        // GRID SELECTION
        // ============================================================

        private void HarGrid_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e)
        {
            if (HarGrid.SelectedItem
                is not HarItem item)
            {
                return;
            }

            ShowRequest(
                item.Entry);

            ShowResponse(
                item.Entry);

            ShowResponseBody(
                item.Entry);
        }

        // ============================================================
        // REQUEST
        // ============================================================

        private void ShowRequest(
            JsonElement entry)
        {
            if (!entry.TryGetProperty(
                    "request",
                    out JsonElement request))
            {
                RequestText.Text = "";

                return;
            }

            StringBuilder output =
                new();

            string method =
                GetStringProperty(
                    request,
                    "method");

            string url =
                GetStringProperty(
                    request,
                    "url");

            string httpVersion =
                GetStringProperty(
                    request,
                    "httpVersion");

            output.AppendLine(
                $"{method} {url} {httpVersion}");

            output.AppendLine();

            AppendHeaders(
                output,
                request);

            // --------------------------------------------------------
            // Query string
            // --------------------------------------------------------

            if (request.TryGetProperty(
                    "queryString",
                    out JsonElement queryString) &&
                queryString.ValueKind ==
                    JsonValueKind.Array &&
                queryString.GetArrayLength() > 0)
            {
                output.AppendLine();

                output.AppendLine(
                    "---------------- QUERY STRING ----------------");

                output.AppendLine();

                foreach (
                    JsonElement parameter
                    in queryString.EnumerateArray())
                {
                    string name =
                        GetStringProperty(
                            parameter,
                            "name");

                    string value =
                        GetStringProperty(
                            parameter,
                            "value");

                    output.AppendLine(
                        $"{name} = {value}");
                }
            }

            // --------------------------------------------------------
            // POST data
            // --------------------------------------------------------

            if (request.TryGetProperty(
                    "postData",
                    out JsonElement postData))
            {
                output.AppendLine();

                output.AppendLine(
                    "---------------- REQUEST BODY ----------------");

                output.AppendLine();

                string mimeType =
                    GetStringProperty(
                        postData,
                        "mimeType");

                if (!string.IsNullOrWhiteSpace(
                        mimeType))
                {
                    output.AppendLine(
                        $"Content-Type: {mimeType}");

                    output.AppendLine();
                }

                if (postData.TryGetProperty(
                        "text",
                        out JsonElement body))
                {
                    string text =
                        body.GetString() ?? "";

                    string encoding =
                        GetStringProperty(
                            postData,
                            "encoding");

                    if (encoding.Equals(
                            "base64",
                            StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            byte[] bytes =
                                System.Convert.FromBase64String(
                                    text);

                            if (LooksLikeText(bytes))
                            {
                                text =
                                    Encoding.UTF8.GetString(
                                        bytes);
                            }
                            else
                            {
                                output.AppendLine(
                                    $"[Binary request body: " +
                                    $"{FormatBytes(bytes.Length)}]");

                                RequestText.Text =
                                    output.ToString();

                                return;
                            }
                        }
                        catch
                        {
                            output.AppendLine(
                                "[Unable to decode Base64 request body]");

                            RequestText.Text =
                                output.ToString();

                            return;
                        }
                    }

                    output.AppendLine(
                        PrettyPrintJson(text));
                }
            }

            RequestText.Text =
                output.ToString();
        }

        // ============================================================
        // RESPONSE
        // ============================================================

        private void ShowResponse(
            JsonElement entry)
        {
            if (!entry.TryGetProperty(
                    "response",
                    out JsonElement response))
            {
                ResponseText.Text = "";

                return;
            }

            StringBuilder output =
                new();

            string httpVersion =
                GetStringProperty(
                    response,
                    "httpVersion");

            int status =
                GetIntProperty(
                    response,
                    "status");

            string statusText =
                GetStringProperty(
                    response,
                    "statusText");

            output.AppendLine(
                $"{httpVersion} {status} {statusText}");

            output.AppendLine();

            AppendHeaders(
                output,
                response);

            if (response.TryGetProperty(
                    "content",
                    out JsonElement content))
            {
                output.AppendLine();

                output.AppendLine(
                    "---------------- CONTENT ----------------");

                output.AppendLine();

                string mimeType =
                    GetStringProperty(
                        content,
                        "mimeType");

                long size =
                    GetLongProperty(
                        content,
                        "size");

                output.AppendLine(
                    $"MIME Type: {mimeType}");

                output.AppendLine(
                    $"Size: {FormatBytes(size)}");
            }

            ResponseText.Text =
                output.ToString();
        }

        // ============================================================
        // RESPONSE BODY
        // ============================================================

        private void ShowResponseBody(
            JsonElement entry)
        {
            BodyText.Text = "";

            if (!entry.TryGetProperty(
                    "response",
                    out JsonElement response))
            {
                BodyText.Text =
                    "(No response)";

                return;
            }

            if (!response.TryGetProperty(
                    "content",
                    out JsonElement content))
            {
                BodyText.Text =
                    "(No response content)";

                return;
            }

            if (!content.TryGetProperty(
                    "text",
                    out JsonElement textElement))
            {
                BodyText.Text =
                    "(No response body recorded in the HAR)";

                return;
            }

            string text =
                textElement.GetString() ?? "";

            if (string.IsNullOrEmpty(text))
            {
                BodyText.Text =
                    "(Empty response body)";

                return;
            }

            string encoding =
                GetStringProperty(
                    content,
                    "encoding");

            if (encoding.Equals(
                    "base64",
                    StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    byte[] bytes =
                        System.Convert.FromBase64String(
                            text);

                    if (LooksLikeText(bytes))
                    {
                        text =
                            Encoding.UTF8.GetString(
                                bytes);
                    }
                    else
                    {
                        string mimeType =
                            GetStringProperty(
                                content,
                                "mimeType");

                        BodyText.Text =
                            "Binary response body\n\n" +

                            $"MIME Type: {mimeType}\n" +

                            $"Size: " +
                            $"{FormatBytes(bytes.Length)}\n" +

                            "Encoding: Base64";

                        return;
                    }
                }
                catch
                {
                    BodyText.Text =
                        "(Unable to decode Base64 response body)";

                    return;
                }
            }

            BodyText.Text =
                PrettyPrintJson(text);
        }

        // ============================================================
        // HEADERS
        // ============================================================

        private static void AppendHeaders(
            StringBuilder output,
            JsonElement parent)
        {
            if (!parent.TryGetProperty(
                    "headers",
                    out JsonElement headers))
            {
                return;
            }

            if (headers.ValueKind !=
                JsonValueKind.Array)
            {
                return;
            }

            foreach (
                JsonElement header
                in headers.EnumerateArray())
            {
                string name =
                    GetStringProperty(
                        header,
                        "name");

                string value =
                    GetStringProperty(
                        header,
                        "value");

                output.AppendLine(
                    $"{name}: {value}");
            }
        }

        // ============================================================
        // ABOUT
        // ============================================================

        private void About_Click(
            object sender,
            RoutedEventArgs e)
        {
            MessageBox.Show(
                "HAR Analyzer V2\n\n" +

                "HAR analysis and Fiddler SAZ → HAR conversion\n\n" +

                "By Andrei-Emilian Rachita\n" +
                "(C) 2026 PhoeNIXBird Networks\n" +
                "www.pbnet.ro",

                "About HAR Analyzer V2",

                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        // ============================================================
        // JSON PROPERTY HELPERS
        // ============================================================

        private static string GetStringProperty(
            JsonElement element,
            string propertyName)
        {
            if (!element.TryGetProperty(
                    propertyName,
                    out JsonElement value))
            {
                return "";
            }

            if (value.ValueKind ==
                JsonValueKind.String)
            {
                return value.GetString() ?? "";
            }

            return "";
        }

        private static int GetIntProperty(
            JsonElement element,
            string propertyName)
        {
            if (!element.TryGetProperty(
                    propertyName,
                    out JsonElement value))
            {
                return 0;
            }

            if (value.ValueKind ==
                    JsonValueKind.Number &&
                value.TryGetInt32(
                    out int result))
            {
                return result;
            }

            return 0;
        }

        private static long GetLongProperty(
            JsonElement element,
            string propertyName)
        {
            if (!element.TryGetProperty(
                    propertyName,
                    out JsonElement value))
            {
                return 0;
            }

            if (value.ValueKind ==
                    JsonValueKind.Number &&
                value.TryGetInt64(
                    out long result))
            {
                return result;
            }

            return 0;
        }

        private static double GetDoubleProperty(
            JsonElement element,
            string propertyName)
        {
            if (!element.TryGetProperty(
                    propertyName,
                    out JsonElement value))
            {
                return 0;
            }

            if (value.ValueKind ==
                    JsonValueKind.Number &&
                value.TryGetDouble(
                    out double result))
            {
                return result;
            }

            return 0;
        }

        // ============================================================
        // JSON PRETTY PRINT
        // ============================================================

        private static string PrettyPrintJson(
            string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                return text;

            string trimmed =
                text.TrimStart();

            if (!trimmed.StartsWith("{") &&
                !trimmed.StartsWith("["))
            {
                return text;
            }

            try
            {
                using JsonDocument document =
                    JsonDocument.Parse(text);

                return JsonSerializer.Serialize(
                    document.RootElement,
                    new JsonSerializerOptions
                    {
                        WriteIndented = true
                    });
            }
            catch
            {
                return text;
            }
        }

        // ============================================================
        // BINARY / TEXT DETECTION
        // ============================================================

        private static bool LooksLikeText(
            byte[] data)
        {
            if (data.Length == 0)
                return true;

            int sampleLength =
                Math.Min(
                    data.Length,
                    4096);

            int controlCharacters = 0;

            for (
                int i = 0;
                i < sampleLength;
                i++)
            {
                byte value =
                    data[i];

                if (value == 0)
                    return false;

                if (
                    value < 9 ||
                    (value > 13 &&
                     value < 32))
                {
                    controlCharacters++;
                }
            }

            return
                controlCharacters <
                sampleLength * 0.05;
        }

        // ============================================================
        // BYTE SIZE FORMATTING
        // ============================================================

        private static string FormatBytes(
            long bytes)
        {
            if (bytes < 1024)
            {
                return
                    $"{bytes:N0} bytes";
            }

            if (bytes <
                1024L * 1024L)
            {
                return
                    $"{bytes / 1024.0:N1} KB";
            }

            if (bytes <
                1024L *
                1024L *
                1024L)
            {
                return
                    $"{bytes / 1024.0 / 1024.0:N2} MB";
            }

            return
                $"{bytes / 1024.0 / 1024.0 / 1024.0:N2} GB";
        }
    }

    // ================================================================
    // HAR GRID MODEL
    // ================================================================

    public class HarItem
    {
        public string Method { get; set; } = "";

        public int Status { get; set; }

        public string Host { get; set; } = "";

        public string Url { get; set; } = "";

        public double TimeValue { get; set; }

        public JsonElement Entry { get; set; }

        public string Time
        {
            get
            {
                if (TimeValue >= 1000)
                {
                    return
                        $"{TimeValue / 1000.0:0.00} s";
                }

                return
                    $"{TimeValue:0} ms";
            }
        }
    }
}