#include "file_searcher.hpp"
#include "shared_types.h"

using namespace nova::types;

void file_searcher_t::init(nova::Context _context, nova::Queue _queue)
{
    context = _context;
    queue = _queue;

    search_shader  = nova::Shader::Create(context, nova::ShaderLang::Slang, nova::ShaderStage::Compute, "search",  "string_search.slang");
    collate_shader = nova::Shader::Create(context, nova::ShaderLang::Slang, nova::ShaderStage::Compute, "collate", "node_collate.slang");

    file_node_buf            = nova::Buffer::Create(context, 0, nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    string_data_buf          = nova::Buffer::Create(context, 0, nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    string_offset_buf        = nova::Buffer::Create(context, 0, nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    keyword_buf              = nova::Buffer::Create(context, 0, nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    keyword_offset_buf       = nova::Buffer::Create(context, 0, nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    string_match_mask_buf    = nova::Buffer::Create(context, 0, nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    file_match_mask_buf      = nova::Buffer::Create(context, 0, nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    file_match_mask_buf_host = nova::Buffer::Create(context, 0, nova::BufferUsage::Storage, nova::BufferFlags::Mapped);
}

void file_searcher_t::destroy()
{
    file_match_mask_buf_host.Destroy();
    file_match_mask_buf.Destroy();
    string_match_mask_buf.Destroy();
    keyword_offset_buf.Destroy();
    keyword_buf.Destroy();
    string_offset_buf.Destroy();
    string_data_buf.Destroy();
    file_node_buf.Destroy();
    collate_shader.Destroy();
    search_shader.Destroy();
}

void file_searcher_t::set_index(index_t& _index)
{
    auto start = std::chrono::steady_clock::now();

    index = &_index;

    file_node_buf.Resize(index->file_nodes.size() * sizeof(file_node_t));
    file_node_buf.Set<file_node_t>(index->file_nodes);

    string_data_buf.Resize(index->string_data.size());
    string_data_buf.Set<char>(index->string_data);

    string_offset_buf.Resize(index->string_offsets.size() * sizeof(index->string_offsets[0]));
    string_offset_buf.Set<uint32_t>(index->string_offsets);

    string_match_mask_buf.Resize(index->string_offsets.size() - 1);

    file_match_mask_buf.Resize(index->file_nodes.size());
    file_match_mask_buf_host.Resize(index->file_nodes.size());

    auto end = std::chrono::steady_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "Updated GPU index in " << dur << " ms\n";
}

void file_searcher_t::filter(nova::Span<std::string_view> keywords)
{
    auto start = std::chrono::steady_clock::now();

    uint32_t keywords_len = 0;
    for (auto keyword : keywords) {
        keywords_len += uint32_t(keyword.size());
    }

    keyword_buf.Resize(keywords_len);
    keyword_offset_buf.Resize((keywords.size() + 1) * sizeof(uint32_t));

    uint32_t keyword_offset = 0;
    for (uint32_t i = 0; i < keywords.size(); ++i) {
        auto& keyword = keywords[i];
        char* buf = (char*)(keyword_buf.HostAddress() + keyword_offset);
        for (uint32_t j = 0; j < keyword.size(); ++j) {
            buf[j] = char(std::tolower(keyword[j]));
        }
        keyword_offset_buf.Set<uint32_t>({ keyword_offset }, i);
        keyword_offset += uint32_t(keywords[i].size());
    }
    keyword_offset_buf.Set<uint32_t>({ keyword_offset }, keywords.size());

    // Run filter

    search_push_constants_t search_pcs {
        .string_data     = (const uint8_t *)string_data_buf.DeviceAddress(),
        .string_offsets  = (const uint32_t*)string_offset_buf.DeviceAddress(),
        .keywords        = (const uint8_t *)keyword_buf.DeviceAddress(),
        .keyword_offsets = (const uint32_t*)keyword_offset_buf.DeviceAddress(),
        .match_output    = (      uint8_t *)string_match_mask_buf.DeviceAddress(),

        .string_count  = uint32_t(index->string_offsets.size() - 1),
        .keyword_count = uint32_t(keywords.size()),
    };

    collate_push_constants_t collate_pcs {
        .match_mask_in  = (const uint8_t    *)string_match_mask_buf.DeviceAddress(),
        .nodes          = (const file_node_t*)file_node_buf.DeviceAddress(),
        .match_mask_out = (      uint8_t    *)file_match_mask_buf.DeviceAddress(),

        .node_count  = uint32_t(index->file_nodes.size()),
        .target_mask = uint32_t(1 << keywords.size()) - 1,
    };

    constexpr uint32_t workgroup_size = 128;

    auto cmd = queue.Begin();

    cmd.BindShaders({ search_shader });
    cmd.PushConstants(search_pcs);
    cmd.Dispatch({(search_pcs.string_count + workgroup_size - 1) / workgroup_size, 1, 1});

    cmd.BindShaders({ collate_shader });
    cmd.PushConstants(collate_pcs);
    cmd.Barrier(nova::PipelineStage::Compute, nova::PipelineStage::Compute);
    cmd.Dispatch({(collate_pcs.node_count + workgroup_size - 1) / workgroup_size, 1, 1});

    cmd.Barrier(nova::PipelineStage::Compute, nova::PipelineStage::Transfer);
    cmd.CopyToBuffer(file_match_mask_buf_host, file_match_mask_buf, index->file_nodes.size());

    queue.Submit({cmd}, {}).Wait();

    auto end = std::chrono::steady_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    // Check results

    uint32_t file_count = 0;
    {
        const uint8_t* mask = reinterpret_cast<const uint8_t*>(file_match_mask_buf_host.HostAddress());
        const uint32_t s = uint32_t(index->file_nodes.size());
        for (uint32_t j = 0; j < s; ++j) {
            file_count += mask[j];
        }
    }

    std::cout << "Found " << file_count << " files in " << dur << " us\n";
}

bool file_searcher_t::is_matched(uint32_t i)
{
    if (i == UINT_MAX)
        return false;
    return reinterpret_cast<const uint8_t*>(file_match_mask_buf_host.HostAddress())[i];
}

uint32_t file_searcher_t::find_next_file(uint32_t i)
{
    const uint32_t size = uint32_t(index->file_nodes.size());
    const uint8_t* mask = reinterpret_cast<const uint8_t*>(file_match_mask_buf_host.HostAddress());
    while (++i < size) {
        if (mask[i]) {
            return i;
        }
    }
    return UINT_MAX;
}

uint32_t file_searcher_t::find_prev_file(uint32_t i)
{
    if (i == UINT_MAX)
        i = uint32_t(index->file_nodes.size());
    const uint8_t* mask = reinterpret_cast<const uint8_t*>(file_match_mask_buf_host.HostAddress());
    while (i > 0) {
        if (mask[--i]) {
            return i;
        }
    }
    return UINT_MAX;
}
