using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using SubParser.Models;
using SubParser.Parsers;

namespace SubParser.Gui.Views;

public partial class MainWindow : Window
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        TypeInfoResolver = SubParserJsonContext.Default,
    };

    private static readonly HttpClient SharedHttpClient = new(
        new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(2) }
    )
    {
        Timeout = TimeSpan.FromSeconds(15),
    };

    static MainWindow()
    {
        SharedHttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("clash.meta");
    }

    public MainWindow()
    {
        InitializeComponent();
    }

    private void OnTitleBarPointerPressed(object? sender, PointerPressedEventArgs e)
    {
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            if (e.ClickCount == 2)
            {
                WindowState =
                    WindowState == WindowState.Maximized
                        ? WindowState.Normal
                        : WindowState.Maximized;
            }
            else
            {
                BeginMoveDrag(e);
            }
        }
    }

    private void OnInputDragOver(object? sender, DragEventArgs e)
    {
        if (e.Data.Contains(DataFormats.Files))
        {
            e.DragEffects = DragDropEffects.Copy;
        }
        else
        {
            e.DragEffects = DragDropEffects.None;
        }
    }

    private async void OnInputDrop(object? sender, DragEventArgs e)
    {
        if (!e.Data.Contains(DataFormats.Files))
            return;

        var files = e.Data.GetFiles();
        if (files == null)
            return;

        foreach (var file in files)
        {
            try
            {
                if (file is IStorageFile storageFile)
                {
                    await using var stream = await storageFile.OpenReadAsync().ConfigureAwait(true);
                    using var reader = new StreamReader(stream);
                    string content = await reader.ReadToEndAsync().ConfigureAwait(true);
                    InputTextBox.Text = content;
                    break;
                }
                else if (file.Path.IsFile)
                {
                    string content = await File.ReadAllTextAsync(file.Path.LocalPath)
                        .ConfigureAwait(true);
                    InputTextBox.Text = content;
                    break;
                }
            }
            catch (Exception ex)
            {
                OutputTextBox.Text = $"读取文件失败: {ex.Message}";
            }
        }
    }

    private async void OnBrowseFileClick(object? sender, RoutedEventArgs e)
    {
        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
            return;

        var files = await topLevel
            .StorageProvider.OpenFilePickerAsync(
                new FilePickerOpenOptions
                {
                    Title = "选择订阅或配置文件",
                    AllowMultiple = false,
                    FileTypeFilter =
                    [
                        new FilePickerFileType("支持的文件 (*.yaml, *.yml, *.txt, *.json)")
                        {
                            Patterns = ["*.yaml", "*.yml", "*.txt", "*.json", "*.*"],
                        },
                    ],
                }
            )
            .ConfigureAwait(true);

        if (files.Count > 0)
        {
            try
            {
                await using var stream = await files[0].OpenReadAsync().ConfigureAwait(true);
                using var reader = new StreamReader(stream);
                string content = await reader.ReadToEndAsync().ConfigureAwait(true);
                InputTextBox.Text = content;
            }
            catch (Exception ex)
            {
                OutputTextBox.Text = $"读取文件失败: {ex.Message}";
            }
        }
    }

    private void OnClearInputClick(object? sender, RoutedEventArgs e)
    {
        InputTextBox.Text = string.Empty;
        OutputTextBox.Text = string.Empty;
        InitialBadge.IsVisible = true;
        NodeCountBadge.IsVisible = false;
        FilteredBadge.IsVisible = false;
    }

    private async void OnConvertClick(object? sender, RoutedEventArgs e)
    {
        string rawInput = InputTextBox.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(rawInput))
        {
            OutputTextBox.Text = "请输入订阅链接、Base64 文本或拖入配置文件。";
            return;
        }

        ConvertButton.IsEnabled = false;
        ConvertButtonText.Text = "正在解析...";

        try
        {
            string content;
            if (
                Uri.TryCreate(rawInput, UriKind.Absolute, out Uri? uri)
                && (
                    string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(
                        uri.Scheme,
                        Uri.UriSchemeHttps,
                        StringComparison.OrdinalIgnoreCase
                    )
                )
            )
            {
                ConvertButtonText.Text = "拉取远程订阅...";
                content = await SharedHttpClient.GetStringAsync(uri).ConfigureAwait(true);
            }
            else
            {
                content = rawInput;
            }

            bool filterAds = FilterAdsCheckBox.IsChecked == true;
            ConvertButtonText.Text = "正在清洗与对齐...";
            var (outbounds, filteredCount) = await Task.Run(() =>
                    UniversalParser.ParseSubscriptionWithStats(content, filterAds)
                )
                .ConfigureAwait(true);

            int nodeCount = outbounds.Count;

            string json = JsonSerializer.Serialize(
                outbounds,
                typeof(IReadOnlyList<SingboxOutbound>),
                JsonOptions
            );

            OutputTextBox.Text = json;

            // 状态徽标更新
            InitialBadge.IsVisible = false;
            NodeCountBadge.IsVisible = true;
            NodeCountText.Text = $"{nodeCount} 个有效节点";

            if (filterAds && filteredCount > 0)
            {
                FilteredBadge.IsVisible = true;
                FilteredText.Text = $"已过滤 {filteredCount} 个提示节点";
            }
            else
            {
                FilteredBadge.IsVisible = false;
            }
        }
        catch (Exception ex)
        {
            OutputTextBox.Text = $"解析失败: {ex.Message}";
        }
        finally
        {
            ConvertButton.IsEnabled = true;
            ConvertButtonText.Text = "解析并转换";
        }
    }

    private async void OnCopyClick(object? sender, RoutedEventArgs e)
    {
        string text = OutputTextBox.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(text))
            return;

        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel?.Clipboard != null)
        {
            await topLevel.Clipboard.SetTextAsync(text).ConfigureAwait(true);
            CopyButtonText.Text = "已复制";
            await Task.Delay(1500).ConfigureAwait(true);
            CopyButtonText.Text = "复制配置";
        }
    }

    private async void OnSaveClick(object? sender, RoutedEventArgs e)
    {
        string text = OutputTextBox.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(text))
            return;

        var topLevel = TopLevel.GetTopLevel(this);
        if (topLevel == null)
            return;

        var file = await topLevel
            .StorageProvider.SaveFilePickerAsync(
                new FilePickerSaveOptions
                {
                    Title = "保存 sing-box 配置文件",
                    DefaultExtension = "json",
                    SuggestedFileName = "config.json",
                    FileTypeChoices =
                    [
                        new FilePickerFileType("JSON 配置文件 (*.json)") { Patterns = ["*.json"] },
                    ],
                }
            )
            .ConfigureAwait(true);

        if (file != null)
        {
            try
            {
                await using var stream = await file.OpenWriteAsync().ConfigureAwait(true);
                await using var writer = new StreamWriter(stream);
                await writer.WriteAsync(text).ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                OutputTextBox.Text = $"保存文件失败: {ex.Message}";
            }
        }
    }
}
