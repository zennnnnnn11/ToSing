using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using ToSing.Gui.Services;
using ToSing.Models;
using ToSing.Models.Protocols;
using ToSing.Parsers;

namespace ToSing.Gui.Views;

public partial class MainWindow : Window
{
    private static readonly FontFamily UiFontFamily = new("MiSans, -apple-system, sans-serif");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        TypeInfoResolver = ToSingJsonContext.Default,
    };

    private readonly FilterRuleService _filterService = new();

    private string? _lastValidConfigJson;
    private long _currentTaskId;

    public MainWindow()
    {
        InitializeComponent();
        CopyButton.IsEnabled = false;
        SaveButton.IsEnabled = false;

        KeywordsItemsControl.ItemsSource = _filterService.Keywords;
        UpdateKeywordCount();
        _filterService.Keywords.CollectionChanged += (_, _) => UpdateKeywordCount();
    }

    private void UpdateKeywordCount()
    {
        KeywordCountText.Text = $"{_filterService.Keywords.Count} 个";
        if (KeywordBadgeText != null)
        {
            KeywordBadgeText.Text = _filterService.Keywords.Count.ToString();
        }
        if (EmptyKeywordsNotice != null)
        {
            EmptyKeywordsNotice.IsVisible = _filterService.Keywords.Count == 0;
        }
    }

    private void OnRemoveKeywordClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string word })
        {
            _filterService.RemoveKeyword(word);
        }
    }

    private void OnAddKeywordClick(object? sender, RoutedEventArgs e)
    {
        AddNewKeywordFromInput();
    }

    private void OnNewKeywordKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            AddNewKeywordFromInput();
            e.Handled = true;
        }
    }

    private void AddNewKeywordFromInput()
    {
        string? text = NewKeywordTextBox.Text?.Trim();
        if (!string.IsNullOrWhiteSpace(text))
        {
            var parts = text.Split(
                [' ', ',', '，', ';', '；', '|'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries
            );
            _filterService.AddKeywords(parts);
            NewKeywordTextBox.Text = string.Empty;
        }
    }

    private void OnResetKeywordsClick(object? sender, RoutedEventArgs e)
    {
        _filterService.ResetToDefault();
    }

    private void OnClearKeywordsClick(object? sender, RoutedEventArgs e)
    {
        _filterService.ClearAll();
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
        if (e.DataTransfer.Formats.Contains(DataFormat.File))
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
        if (!e.DataTransfer.Formats.Contains(DataFormat.File))
            return;

        var files = e.DataTransfer.TryGetFiles();
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
                OutputTextBox.Text = $"// 读取文件失败: {ex.Message}";
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
        Interlocked.Increment(ref _currentTaskId);
        _lastValidConfigJson = null;
        InputTextBox.Text = string.Empty;
        OutputTextBox.Text = string.Empty;
        InitialBadge.IsVisible = true;
        NodeCountBadge.IsVisible = false;
        FilteredBadge.IsVisible = false;
        ToolTip.SetTip(NodeCountBadge, null);
        CopyButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        ConvertButton.IsEnabled = true;
        ConvertButtonText.Text = "解析并转换";
    }

    private async void OnConvertClick(object? sender, RoutedEventArgs e)
    {
        string rawInput = InputTextBox.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(rawInput))
        {
            _lastValidConfigJson = null;
            OutputTextBox.Text = "请输入订阅链接、Base64 文本或拖入配置文件。";
            InitialBadge.IsVisible = true;
            NodeCountBadge.IsVisible = false;
            FilteredBadge.IsVisible = false;
            ToolTip.SetTip(NodeCountBadge, null);
            CopyButton.IsEnabled = false;
            SaveButton.IsEnabled = false;
            return;
        }

        long taskId = Interlocked.Increment(ref _currentTaskId);
        ConvertButton.IsEnabled = false;
        ConvertButtonText.Text = "正在解析并聚合...";

        try
        {
            bool filterAds = FilterAdsCheckBox.IsChecked == true;
            var keywords = filterAds ? _filterService.Keywords.ToList() : null;

            // 将密集计算移至后台线程，保证 UI 界面永不卡顿
            var (outbounds, filteredCount, json) = await Task.Run(async () =>
            {
                var (nodes, filtered) = await UniversalParser
                    .ParseMixedSubscriptionWithStatsAsync(
                        rawInput,
                        filterAds: filterAds,
                        filterKeywords: keywords
                    )
                    .ConfigureAwait(false);

                string serialized = JsonSerializer.Serialize(
                    nodes,
                    ToSingJsonContext.Default.IReadOnlyListSingboxOutbound
                );

                return (nodes, filtered, serialized);
            }).ConfigureAwait(true);

            // 如果在此期间用户触发了清空或新的转换，舍弃本次旧任务结果
            if (taskId != Volatile.Read(ref _currentTaskId))
                return;

            int nodeCount = outbounds.Count;
            _lastValidConfigJson = nodeCount > 0 ? json : null;

            OutputTextBox.Text = FormatPreviewText(json);
            CopyButton.IsEnabled = nodeCount > 0;
            SaveButton.IsEnabled = nodeCount > 0;

            // 状态徽标更新
            InitialBadge.IsVisible = false;
            NodeCountBadge.IsVisible = true;
            NodeCountText.Text = $"{nodeCount} 个有效节点";
            UpdateProtocolDistributionTooltip(outbounds);

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
            if (taskId == Volatile.Read(ref _currentTaskId))
            {
                _lastValidConfigJson = null;
                OutputTextBox.Text = $"// 聚合解析失败: {ex.Message}";
                CopyButton.IsEnabled = false;
                SaveButton.IsEnabled = false;
            }
        }
        finally
        {
            if (taskId == Volatile.Read(ref _currentTaskId))
            {
                ConvertButton.IsEnabled = true;
                ConvertButtonText.Text = "解析并转换";
            }
        }
    }

    private void UpdateProtocolDistributionTooltip(IReadOnlyList<SingboxOutbound> outbounds)
    {
        // 8 个已知出站类型 + 1 个未知
        var orderedKeys = new[]
        {
            "VLESS",
            "VMess",
            "Trojan",
            "Shadowsocks",
            "Hysteria2",
            "TUIC",
            "AnyTLS",
            "WireGuard",
            "未知出站",
        };

        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["VLESS"] = 0,
            ["VMess"] = 0,
            ["Trojan"] = 0,
            ["Shadowsocks"] = 0,
            ["Hysteria2"] = 0,
            ["TUIC"] = 0,
            ["AnyTLS"] = 0,
            ["WireGuard"] = 0,
            ["未知出站"] = 0,
        };

        foreach (var outbound in outbounds)
        {
            string type = outbound switch
            {
                VlessOutbound => "VLESS",
                VmessOutbound => "VMess",
                TrojanOutbound => "Trojan",
                ShadowsocksOutbound => "Shadowsocks",
                Hysteria2Outbound => "Hysteria2",
                TuicOutbound => "TUIC",
                AnyTlsOutbound => "AnyTLS",
                WireguardOutbound => "WireGuard",
                _ => "未知出站",
            };
            counts[type]++;
        }

        var panel = new StackPanel { Spacing = 4, MinWidth = 150 };

        panel.Children.Add(
            new TextBlock
            {
                Text = "出站协议分布",
                FontFamily = UiFontFamily,
                FontSize = 11.5,
                FontWeight = FontWeight.SemiBold,
                Foreground = Brush.Parse("#1E293B"),
                Margin = new Thickness(0, 0, 0, 4),
            }
        );

        panel.Children.Add(
            new Border
            {
                Height = 1,
                Background = Brush.Parse("#E2E8F0"),
                Margin = new Thickness(0, 0, 0, 4),
            }
        );

        int activeTypes = 0;
        foreach (string key in orderedKeys)
        {
            int count = counts[key];
            if (count <= 0) // 没有的话绝对不展示！
                continue;

            activeTypes++;

            var row = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("Auto, *, Auto"),
                Margin = new Thickness(0, 2),
            };

            var tagBorder = new Border
            {
                Background = Brush.Parse("#F8FAFC"),
                BorderBrush = Brush.Parse("#E2E8F0"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(3),
                Padding = new Thickness(5, 1.5),
            };
            tagBorder.Child = new TextBlock
            {
                Text = key,
                FontFamily = UiFontFamily,
                FontSize = 11,
                FontWeight = FontWeight.Medium,
                Foreground = Brush.Parse("#334155"),
            };

            var countText = new TextBlock
            {
                Text = $"{count} 个",
                FontFamily = UiFontFamily,
                FontSize = 11,
                Foreground = Brush.Parse("#64748B"),
                VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center,
            };
            Grid.SetColumn(countText, 2);

            row.Children.Add(tagBorder);
            row.Children.Add(countText);
            panel.Children.Add(row);
        }

        if (activeTypes == 0)
        {
            ToolTip.SetTip(NodeCountBadge, null);
            return;
        }

        var container = new Border
        {
            Background = Brush.Parse("#FFFFFF"),
            BorderBrush = Brush.Parse("#CBD5E1"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(10, 8),
            BoxShadow = new BoxShadows(
                new BoxShadow
                {
                    Blur = 12,
                    OffsetY = 4,
                    Color = Color.FromArgb(30, 0, 0, 0),
                }
            ),
            Child = panel,
        };

        ToolTip.SetTip(NodeCountBadge, container);
    }

    private const int MaxPreviewCharacters = 65536;

    private static string FormatPreviewText(string json)
    {
        if (json.Length <= MaxPreviewCharacters)
        {
            return json;
        }

        int cutIndex = json.LastIndexOf('\n', MaxPreviewCharacters);
        if (cutIndex <= 0)
        {
            cutIndex = MaxPreviewCharacters;
        }

        return json[..cutIndex] + "\r\n\r\n// ...... (节点较多，此处仅预览前部配置；点击下方【复制配置】或【保存文件】可获取完整全部配置)";
    }

    private async void OnCopyClick(object? sender, RoutedEventArgs e)
    {
        string? text = _lastValidConfigJson ?? OutputTextBox.Text?.Trim();
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
        string? text = _lastValidConfigJson ?? OutputTextBox.Text?.Trim();
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
