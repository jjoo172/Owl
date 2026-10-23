#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace app {

struct ConfigEntry {
    std::string_view key;
    std::string_view value;
};

// Trims leading and trailing whitespace without copying.
std::string_view trim(std::string_view s);

// Parses "key = value" lines. Blank lines and '#' comments are ignored.
std::vector<ConfigEntry> parse_config(const std::string& text);

using Settings = std::unordered_map<std::string, std::string>;

Settings to_settings(const std::vector<ConfigEntry>& entries);

// Returns the setting for `key`, or `fallback` if it is not present.
const std::string& get_or(const Settings& settings, const std::string& key,
                          const std::string& fallback = "");

}  // namespace app
