#include "file_indexer.hpp"

#include "strings.hpp"

#include <format>
#include <iostream>
#include <chrono>
#include <fstream>
#include <algorithm>
#include <execution>

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
uint32_t insert_node(indexer_t& indexer, std::string_view view, uint32_t parent)
{
    uint32_t node_index = uint32_t(indexer.index->file_nodes.size());

    string_data_source_t source{ view };
    string_slice_t slice{ &source, 0, uint32_t(view.size()) };

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

    return node_index;
}

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

    if (find_handle == INVALID_HANDLE_VALUE) {
        return;
    }

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

        uint32_t node_index = insert_node(indexer, std::string_view(indexer.utf8_buffer, utf8_len), parent);

        if (++indexer.count % 100'000 == 0) {
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
void index_filesystem(indexer_t& indexer, const wchar_t* vol_guid)
{
    auto vol_guid_len = wcslen(vol_guid);
    wcscpy(indexer.path, vol_guid);
    std::wcout << std::format(L"Indexing volume: {}\n", vol_guid);

    wchar_t vol_paths[1024];
    DWORD vol_paths_len = sizeof(vol_paths);
    bool found_vols = GetVolumePathNamesForVolumeNameW(vol_guid, vol_paths, vol_paths_len, &vol_paths_len);
    vol_paths_len = DWORD(wcslen(vol_paths));

    if (!found_vols || vol_paths_len == 0) {
        std::cout << "  No paths for this volume!\n";
        return;
    }

    std::wcout << "  using volume path: [" << vol_paths << "]\n";

    auto utf8_len = simdutf::convert_utf16_to_utf8((const char16_t*)vol_paths, vol_paths_len - 1, indexer.utf8_buffer);
    uint32_t node_index = insert_node(indexer, std::string_view(indexer.utf8_buffer, utf8_len), UINT_MAX);

    search_dir(indexer, vol_guid_len - 1, node_index);
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

void sort_index(index_t& index)
{
    std::vector<uint32_t> depth(index.file_nodes.size());
    std::vector<uint32_t> index_new_to_old(index.file_nodes.size());
    for (uint32_t i = 0; i < index.file_nodes.size(); ++i) {
        index_new_to_old[i] = i;
        uint32_t n = i;
        while (index.file_nodes[n].parent != UINT_MAX) {
            depth[i]++;
            n = index.file_nodes[n].parent;
        }
    }

    auto cmp_len_lex = [&](uint32_t li, uint32_t ri) -> std::weak_ordering {
        using order = std::weak_ordering;

        auto lv = index.get_string(li);
        auto rv = index.get_string(ri);

        auto o = lv.size() != rv.size()
            ? (lv.size() < rv.size() ? order::less : order::greater)
            : (lv <=> rv);

        return o;
    };

    auto cmp_depth_len_lex = [&](this auto&& self, uint32_t li, uint32_t ri) -> std::weak_ordering {
        using order = std::weak_ordering;
        auto& l = index.file_nodes[li];
        auto& r = index.file_nodes[ri];

        if (depth[li] != depth[ri]) {
            return depth[li] < depth[ri] ? order::less : order::greater;
        } else if (l.filename == r.filename) {
            return order::equivalent;
        } else if (depth[li] == 0) {
            return cmp_len_lex(li, ri);
        } else {
            auto o = self(l.parent, r.parent);
            return o == order::equivalent ? cmp_len_lex(l.filename, r.filename) : o;
        }
    };

    auto cmp = [&](uint32_t l, uint32_t r) {
        return cmp_depth_len_lex(l, r) == std::weak_ordering::less;
    };

    std::sort(std::execution::par, index_new_to_old.begin(), index_new_to_old.end(), cmp);

    std::vector<uint32_t> index_old_to_new(index.file_nodes.size());
    for (uint32_t i = 0; i < index.file_nodes.size(); ++i) {
        index_old_to_new[index_new_to_old[i]] = i;
    }

    std::vector<file_node_t> sorted_file_nodes(index.file_nodes.size());
    for (uint32_t i = 0; i < index.file_nodes.size(); ++i) {
        auto node = index.file_nodes[index_new_to_old[i]];

        node.parent = (node.parent == UINT_MAX)
            ? UINT_MAX
            : index_old_to_new[node.parent];

        sorted_file_nodes[i] = node;
    }

    index.file_nodes = std::move(sorted_file_nodes);
}