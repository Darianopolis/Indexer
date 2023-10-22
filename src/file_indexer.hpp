#pragma once

#include "core.hpp"

struct file_node_t
{
    uint32_t parent;
    uint32_t filename;
};

struct index_t
{
    std::vector<char> string_data;
    std::vector<uint32_t> string_offsets;
    std::vector<file_node_t> file_nodes;

    std::string_view get_string(uint32_t index)
    {
        auto begin = string_offsets[index];
        return{ string_data.data() + begin, string_offsets[index + 1] - begin };
    }

    std::string get_full_path(uint32_t node_index)
    {
        auto& node = file_nodes[node_index];
        if (node.parent != UINT_MAX) {
            auto path = get_full_path(node.parent);
            path += '\\';
            path += get_string(node.filename);
            return path;
        } else {
            return std::string(get_string(node.filename));
        }
    }
};

void save_index(const index_t& index, const char* path);
void load_index(index_t& index, const char* path);

void index_filesystem(index_t& index);
void sort_index(index_t& index);