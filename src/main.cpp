#include <file_indexer.hpp>
#include <strings.hpp>

#include <iostream>
#include <chrono>
#include <format>

using namespace std::literals;

int main(int argc, char* argv[])
{
    std::vector<std::string_view> args{ argv, argv + argc };

    using namespace std::chrono;
    auto start = steady_clock::now();

    index_t index;

    if (std::ranges::find(args, "--generate") != args.end()) {
        index_filesystem(index);
        save_index(index, "index.bin");
    } else {
        load_index(index, "index.bin");
    }

    auto end = steady_clock::now();

    std::cout << std::format("Elapsed: {} ms\nFiles/s: {:.2f}\n",
        duration_cast<milliseconds>(end - start).count(),
        index.file_nodes.size() / duration_cast<duration<float>>(end - start).count());

    std::cout << std::format("Stats:\n  Files: {}\n  Unique names: {} ({:.2f}%)\n  String length: {}\n",
        index.file_nodes.size(),
        index.string_offsets.size(),
        (100.0 * index.string_offsets.size()) / index.file_nodes.size(),
        index.string_data.size());

    // Find "program" in all files

    std::string_view needle{ "program" };
    std::vector<uint8_t> matches(index.string_offsets.size() - 1);
    start = steady_clock::now();

#pragma omp parallel for
    for (uint32_t i = 0; i < index.string_offsets.size() - 1; ++i) {
        if (fuzzy_contains(index.get_string(i), needle))
            matches[i] = 1;
    }

    end = steady_clock::now();

    uint32_t match_count = 0;
    for (uint32_t i = 0; i  < index.string_offsets.size() - 1; ++i) {
        if (matches[i]) {
            if (match_count < 10) {
                std::cout << " - " << index.get_string(i) << '\n';
            }
            match_count++;
        }
    }

    std::cout << std::format("Matches found: {}\n", match_count);
    std::cout << std::format("Elapsed: {} ms\nStrings/s: {:.2f}\n",
        duration_cast<milliseconds>(end - start).count(),
        (index.string_offsets.size() - 1) / duration_cast<duration<float>>(end - start).count());

    // Basic statistics over string data

    uint32_t min_size = UINT_MAX, max_size = 0;
    for (uint32_t i = 0; i < index.string_offsets.size() - 1; ++i) {
        auto size = index.string_offsets[i + 1] - index.string_offsets[i];
        min_size = std::min(min_size, size);
        max_size = std::max(max_size, size);
    }
    std::cout << std::format("String size: Avg = {:.2f}, Min = {}, Max = {}\n", double(index.string_data.size()) / (index.string_offsets.size() - 1), min_size, max_size);
}