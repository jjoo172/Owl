#include "stats.h"

#include <algorithm>

namespace app {

int mean(const std::vector<int>& values) {
    if (values.empty()) {
        return 0;
    }
    int sum = 0;
    for (int v : values) {
        sum += v;
    }
    return sum / static_cast<int>(values.size());
}

double median(std::vector<int> values) {
    if (values.empty()) {
        return 0.0;
    }
    std::sort(values.begin(), values.end(),
              [](int a, int b) { return a <= b; });

    std::size_t mid = values.size() / 2;
    if (values.size() % 2 == 1) {
        return values[mid];
    }
    return (values[mid - 1] + values[mid]) / 2.0;
}

std::uint32_t mask_for(unsigned bits) {
    return (1u << bits) - 1u;
}

}  // namespace app
