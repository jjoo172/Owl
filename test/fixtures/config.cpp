#include "config.h"

#include <cctype>
#include <sstream>

namespace app {

std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

std::vector<ConfigEntry> parse_config(const std::string& text) {
    std::vector<ConfigEntry> entries;
    std::istringstream in(text);
    std::string line;

    while (std::getline(in, line)) {
        if (auto hash = line.find('#'); hash != std::string::npos) {
            line.erase(hash);
        }
        auto eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string_view view(line);
        auto key = trim(view.substr(0, eq));
        auto value = trim(view.substr(eq + 1));
        if (!key.empty()) {
            entries.push_back({key, value});
        }
    }
    return entries;
}

Settings to_settings(const std::vector<ConfigEntry>& entries) {
    Settings settings;
    for (const auto& e : entries) {
        settings[std::string(e.key)] = std::string(e.value);
    }
    return settings;
}

const std::string& get_or(const Settings& settings, const std::string& key,
                          const std::string& fallback) {
    auto it = settings.find(key);
    if (it == settings.end()) {
        return fallback;
    }
    return it->second;
}

}  // namespace app
