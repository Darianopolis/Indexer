#include "file_searcher.hpp"

#include "node_collate.glsl.hpp"
#include "string_search.glsl.hpp"

using namespace nova::types;

void file_searcher_t::init(nova::Context _context, nova::Queue _queue)
{
    context = _context;
    queue = _queue;
    pool = nova::CommandPool::Create(context, queue);
    fence = nova::Fence::Create(context);

    search_shader = nova::Shader::Create(context, nova::ShaderLang::Glsl, nova::ShaderStage::Compute, "main", "string_search", { s_string_search_shader_glsl });
    collate_shader = nova::Shader::Create(context, nova::ShaderLang::Glsl, nova::ShaderStage::Compute, "main", "collate_shader", { s_collate_shader_glsl });

    file_node_buf = nova::Buffer::Create(context, 0,
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);

    string_data_buf = nova::Buffer::Create(context, 0,
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);

    string_offset_buf = nova::Buffer::Create(context, 0,
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);

    keyword_buf = nova::Buffer::Create(context, 0,
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    keyword_offset_buf = nova::Buffer::Create(context, 0,
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);

    string_match_mask_buf = nova::Buffer::Create(context, 0,
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);

    file_match_mask_buf = nova::Buffer::Create(context, 0,
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    file_match_mask_buf_host = nova::Buffer::Create(context, 0,
        nova::BufferUsage::Storage, nova::BufferFlags::Mapped);
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
    fence.Destroy();
    pool.Destroy();
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
        char* buf = (char*)(keyword_buf.GetMapped() + keyword_offset);
        for (uint32_t j = 0; j < keyword.size(); ++j) {
            buf[j] = char(std::tolower(keyword[j]));
        }
        keyword_offset_buf.Set<uint32_t>({ keyword_offset }, i);
        keyword_offset += uint32_t(keywords[i].size());
    }
    keyword_offset_buf.Set<uint32_t>({ keyword_offset }, keywords.size());

    // Run filter

    pool.Reset();

    struct search_push_constants_t {
        uint64_t string_data_address;
        uint64_t string_offsets_address;
        uint64_t match_output_address;
        uint64_t keywords_address;
        uint64_t keyword_offset_address;
        uint32_t string_count;
        uint32_t keyword_count;
    } search_pcs;

    search_pcs.string_data_address = string_data_buf.GetAddress();
    search_pcs.string_offsets_address = string_offset_buf.GetAddress();
    search_pcs.match_output_address = string_match_mask_buf.GetAddress();
    search_pcs.keywords_address = keyword_buf.GetAddress();
    search_pcs.keyword_offset_address = keyword_offset_buf.GetAddress();
    search_pcs.string_count = uint32_t(index->string_offsets.size() - 1);
    search_pcs.keyword_count = uint32_t(keywords.size());

    struct collate_push_constants_t {
        uint64_t match_mask_in;
        uint64_t nodes;
        uint64_t match_mask_out;
        uint32_t node_count;
        uint32_t target_mask;
    } collate_pcs;

    collate_pcs.match_mask_in = string_match_mask_buf.GetAddress();
    collate_pcs.nodes = file_node_buf.GetAddress();
    collate_pcs.match_mask_out = file_match_mask_buf.GetAddress();
    collate_pcs.node_count = uint32_t(index->file_nodes.size());
    collate_pcs.target_mask = (1 << keywords.size()) - 1;

    constexpr uint32_t workgroup_size = 128;

    auto cmd = pool.Begin();

    cmd.BindShaders({ search_shader });
    cmd.PushConstants(search_pcs);
    cmd.Dispatch({(search_pcs.string_count + workgroup_size - 1) / workgroup_size, 1, 1});

    cmd.BindShaders({ collate_shader });
    cmd.PushConstants(collate_pcs);
    cmd.Barrier(nova::PipelineStage::Compute, nova::PipelineStage::Compute);
    cmd.Dispatch({(collate_pcs.node_count + workgroup_size - 1) / workgroup_size, 1, 1});

    cmd.Barrier(nova::PipelineStage::Compute, nova::PipelineStage::Transfer);
    cmd.CopyToBuffer(file_match_mask_buf_host, file_match_mask_buf, index->file_nodes.size());

    queue.Submit({cmd}, {}, {fence});
    fence.Wait();

    auto end = std::chrono::steady_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    // Check results

    uint32_t file_count = 0;
    {
        const uint8_t* mask = reinterpret_cast<const uint8_t*>(file_match_mask_buf_host.GetMapped());
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
    return reinterpret_cast<const uint8_t*>(file_match_mask_buf_host.GetMapped())[i];
}

uint32_t file_searcher_t::find_next_file(uint32_t i)
{
    const uint32_t size = uint32_t(index->file_nodes.size());
    const uint8_t* mask = reinterpret_cast<const uint8_t*>(file_match_mask_buf_host.GetMapped());
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
    const uint8_t* mask = reinterpret_cast<const uint8_t*>(file_match_mask_buf_host.GetMapped());
    while (i > 0) {
        if (mask[--i]) {
            return i;
        }
    }
    return UINT_MAX;
}
