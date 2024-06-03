#pragma once

#include <file_indexer.hpp>

#include <nova/rhi/nova_RHI.hpp>

struct file_searcher_t
{
    index_t* index = nullptr;

    nova::Context context;
    nova::Queue queue;

    nova::Shader search_shader;
    nova::Shader collate_shader;

    nova::Buffer string_data_buf;
    nova::Buffer string_offset_buf;
    nova::Buffer string_match_mask_buf;

    nova::Buffer keyword_buf;
    nova::Buffer keyword_offset_buf;

    nova::Buffer file_node_buf;
    nova::Buffer file_match_mask_buf;
    nova::Buffer file_match_mask_buf_host;

public:
    void init(nova::Context context, nova::Queue queue);
    void destroy();

    void set_index(index_t& index);
    void filter(nova::Span<std::string_view> keywords);

    bool is_matched(uint32_t index);
    uint32_t find_next_file(uint32_t index);
    uint32_t find_prev_file(uint32_t index);
};