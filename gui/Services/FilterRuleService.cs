namespace ToSing.Gui.Services;

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using ToSing.Parsers;

public class FilterRuleService
{
    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "ToSing"
    );
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "filter_keywords.json");

    public ObservableCollection<string> Keywords { get; } = new();

    public FilterRuleService()
    {
        Load();
    }

    public void Load()
    {
        Keywords.Clear();
        try
        {
            if (File.Exists(ConfigPath))
            {
                string json = File.ReadAllText(ConfigPath);
                var list = JsonSerializer.Deserialize<List<string>>(json);
                if (list != null)
                {
                    foreach (string w in list)
                    {
                        if (!string.IsNullOrWhiteSpace(w))
                        {
                            Keywords.Add(w.Trim());
                        }
                    }
                    return;
                }
            }
        }
        catch
        {
            // 读取异常时使用默认
        }

        ResetToDefault();
    }

    public void Save()
    {
        try
        {
            if (!Directory.Exists(ConfigDir))
            {
                Directory.CreateDirectory(ConfigDir);
            }
            string json = JsonSerializer.Serialize(
                Keywords.ToList(),
                new JsonSerializerOptions { WriteIndented = true }
            );
            File.WriteAllText(ConfigPath, json);
        }
        catch
        {
            // 忽略文件写入异常
        }
    }

    public bool AddKeyword(string? word)
    {
        if (string.IsNullOrWhiteSpace(word))
            return false;

        string trimmed = word.Trim();
        if (!Keywords.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
        {
            Keywords.Add(trimmed);
            Save();
            return true;
        }
        return false;
    }

    public int AddKeywords(IEnumerable<string> words)
    {
        int added = 0;
        foreach (var word in words)
        {
            if (string.IsNullOrWhiteSpace(word))
                continue;
            string trimmed = word.Trim();
            if (!Keywords.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
            {
                Keywords.Add(trimmed);
                added++;
            }
        }
        if (added > 0)
        {
            Save();
        }
        return added;
    }

    public bool RemoveKeyword(string? word)
    {
        if (string.IsNullOrWhiteSpace(word))
            return false;

        string? existing = Keywords.FirstOrDefault(w =>
            string.Equals(w, word, StringComparison.OrdinalIgnoreCase)
        );
        if (existing != null)
        {
            Keywords.Remove(existing);
            Save();
            return true;
        }
        return false;
    }

    public void ResetToDefault()
    {
        Keywords.Clear();
        foreach (string w in UniversalParser.DefaultFilterKeywords)
        {
            Keywords.Add(w);
        }
        Save();
    }

    public void ClearAll()
    {
        Keywords.Clear();
        Save();
    }
}
