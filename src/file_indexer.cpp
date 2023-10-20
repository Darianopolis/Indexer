#include "file_indexer.hpp"

#include "strings.hpp"

#include <format>
#include <iostream>
#include <chrono>
#include <fstream>

#include <ankerl/unordered_dense.h>

struct index_header_t {
    size_t string_size;
    uint32_t string_offset_count;
    uint32_t file_node_count;
};

void save_index(const index_t& index, const char* path)
{
    std::ofstream out{ path, std::ios::binary };

    index_header_t header{
        .string_size = index.string_data.size(),
        .string_offset_count = uint32_t(index.string_offsets.size()),
        .file_node_count = uint32_t(index.file_nodes.size()),
    };
    std::cout << std::format("Writing index:\n  String size: {}\n  Path components: {}\n  File nodes: {}\n",
        header.string_size, header.string_offset_count, header.file_node_count);
    out.write((const char*)&header, sizeof(header));

    out.write(index.string_data.data(), header.string_size);
    out.write((const char*)index.string_offsets.data(), header.string_offset_count * sizeof(index.string_offsets[0]));
    out.write((const char*)index.file_nodes.data(), header.file_node_count * sizeof(index.file_nodes[0]));
}

void load_index(index_t& index, const char* path)
{
    std::ifstream in{ path, std::ios::binary };

    index_header_t header;
    in.read((char*)&header, sizeof(index_header_t));

    std::cout << std::format("Reading index:\n  String size: {}\n  Path components: {}\n  File nodes: {}\n",
        header.string_size, header.string_offset_count, header.file_node_count);

    index.string_data.resize(header.string_size);
    in.read(index.string_data.data(), header.string_size);

    index.string_offsets.resize(header.string_offset_count);
    in.read((char*)index.string_offsets.data(), header.string_offset_count * sizeof(index.string_offsets[0]));

    index.file_nodes.resize(header.file_node_count);
    in.read((char*)index.file_nodes.data(), header.file_node_count * sizeof(index.file_nodes[0]));
}

struct indexer_t
{
    wchar_t path[32767];
    char utf8_buffer[MAX_PATH * 3 + 1];
    WIN32_FIND_DATA result;
    size_t count = 0;

    index_t* index;
    string_data_source_t string_source;
    ankerl::unordered_dense::map<string_slice_t, uint32_t> dedup_set;
};

static
void search_dir(indexer_t& indexer, size_t offset, uint32_t parent)
{
    indexer.path[offset    ] = '\\';
    indexer.path[offset + 1] =  '*';
    indexer.path[offset + 2] = '\0';

    auto find_handle = FindFirstFileExW(
        indexer.path,
        FindExInfoBasic,
        &indexer.result,
        FindExSearchNameMatch,
        nullptr,
        FIND_FIRST_EX_LARGE_FETCH);

    if (find_handle == INVALID_HANDLE_VALUE)
        return;

    do {
        size_t len = wcslen(indexer.result.cFileName);

        // Ignore empty, current, and parent directories
        if (len == 0
                || (indexer.result.cFileName[0] == '.'
                    && (len == 1
                        || (len == 2 && indexer.result.cFileName[1] == '.')))) {
            continue;
        }

        auto utf8_len = simdutf::convert_utf16_to_utf8(
            (const char16_t*)indexer.result.cFileName, len, indexer.utf8_buffer);

        uint32_t node_index = uint32_t(indexer.index->file_nodes.size());
        {
            std::string_view view{ indexer.utf8_buffer, utf8_len };
            string_data_source_t source{ view };
            string_slice_t slice{ &source, 0, uint32_t(utf8_len) };

            uint32_t string_offset_index;
            auto existing = indexer.dedup_set.find(slice);
            if (existing == indexer.dedup_set.end()) {
                slice.source = &indexer.string_source;
                slice.offset = uint32_t(indexer.index->string_data.size());
                indexer.index->string_data.append_range(view);
                string_offset_index = uint32_t(indexer.index->string_offsets.size());
                indexer.index->string_offsets.emplace_back(slice.offset);
                indexer.dedup_set.insert({ slice, string_offset_index });
            } else {
                string_offset_index = existing->second;
            }

            indexer.index->file_nodes.emplace_back(parent, string_offset_index);
        }

        if (++indexer.count % 10'000 == 0) {
            std::wcout << std::format(L"  File[{}]: {:.{}s}{}\n",
                indexer.count, indexer.path, offset + 1, indexer.result.cFileName);
        }

        if (indexer.result.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            std::memcpy(&indexer.path[offset + 1], indexer.result.cFileName, len * 2);
            search_dir(indexer, offset + len + 1, node_index);
        }

    } while (FindNextFileW(find_handle, &indexer.result));

    FindClose(find_handle);
}

static
void index_filesystem(indexer_t& indexer, const wchar_t* vol)
{
    wcscpy(indexer.path, vol);
    std::wcout << std::format(L"Indexing volume: {}\n", vol);
    search_dir(indexer, wcslen(vol) - 1, UINT_MAX);
}

void index_filesystem(index_t& index)
{
    wchar_t vol[256];
    auto vol_handle = FindFirstVolumeW(vol, 255);

    indexer_t indexer{
        .index = &index,
        .string_source{ index.string_data },
    };

    do {
        index_filesystem(indexer, vol);
    } while (FindNextVolumeW(vol_handle, vol, 255));

    FindVolumeClose(vol_handle);

    index.string_offsets.emplace_back(uint32_t(index.string_data.size()));
}