#include <file_indexer.hpp>
#include <strings.hpp>

#include <file_searcher.hpp>

// #include <nova/rhi/nova_RHI.hpp>
// #include <nova/rhi/vulkan/glsl/nova_VulkanGlsl.hpp>

#include <iostream>
#include <format>

using namespace std::literals;

using namespace nova::types;

int main(int argc, char* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    std::vector<std::string_view> args{ argv, argv + argc };

    using namespace std::chrono;
    auto start = steady_clock::now();

    index_t index;

    if (std::ranges::find(args, "--generate") != args.end()) {
        index_filesystem(index);
        sort_index(index);
        save_index(index, "index.bin");
    } else {
        load_index(index, "index.bin");
        sort_index(index);
        save_index(index, "index.bin");
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

    // Create keywords

    uint32_t keywords_len = 0;
    std::vector<std::string_view> keywords;
    if (auto _needle = std::ranges::find(args, "--find"); _needle == args.end()) {
        std::cout << "Missing search terms, specify with --find\n";
        return 1;
    } else {
        for (_needle++; _needle != args.end() && !_needle->starts_with("--"); _needle++) {
            keywords.emplace_back(*_needle);
            keywords_len += uint32_t(_needle->size());
        }
    }
    std::cout << "Searching for keywords:\n";
    for (auto keyword : keywords) {
        std::cout << std::format(" - {}\n", keyword);
    }
    std::vector<uint8_t> matches(index.string_offsets.size() - 1);

    // Configure Nova RHI

    // start = steady_clock::now();

    auto context = nova::Context::Create({
        .debug = false,
    });
    // auto queue = context.GetQueue(nova::QueueFlags::Compute, 0);
    // auto pool = nova::CommandPool::Create(context, queue);
    // auto fence = nova::Fence::Create(context);

    // auto search_shader = nova::Shader::Create(context, nova::ShaderStage::Compute, "main",
    //     nova::glsl::Compile(nova::ShaderStage::Compute, "main", "src/string_search.glsl"));
    // auto collate_shader = nova::Shader::Create(context, nova::ShaderStage::Compute, "main",
    //     nova::glsl::Compile(nova::ShaderStage::Compute, "main", "src/node_collate.glsl"));

    // auto file_node_buf = nova::Buffer::Create(context, index.file_nodes.size() * sizeof(file_node_t),
    //     nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    // file_node_buf.Set<file_node_t>(index.file_nodes);

    // auto string_data_buf = nova::Buffer::Create(context, index.string_data.size(),
    //     nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    // string_data_buf.Set<char>(index.string_data);

    // auto string_offset_buf = nova::Buffer::Create(context, index.string_offsets.size() * sizeof(index.string_offsets[0]),
    //     nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    // string_offset_buf.Set<uint32_t>(index.string_offsets);

    // auto keyword_buf = nova::Buffer::Create(context, keywords_len,
    //     nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    // auto keyword_offset_buf = nova::Buffer::Create(context, (keywords.size() + 1) * sizeof(uint32_t),
    //     nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    // {
    //     uint32_t keyword_offset = 0;
    //     for (uint32_t i = 0; i < keywords.size(); ++i) {
    //         keyword_buf.Set<char>({ keywords[i].data(), keywords[i].size() }, 0, keyword_offset);
    //         keyword_offset_buf.Set<uint32_t>({ keyword_offset }, i);
    //         keyword_offset += uint32_t(keywords[i].size());
    //     }
    //     keyword_offset_buf.Set<uint32_t>({ keyword_offset }, keywords.size());
    // }

    // auto name_match_mask_buf = nova::Buffer::Create(context, index.string_offsets.size() - 1,
    //     nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    // // auto name_match_mask_buf_host = nova::Buffer::Create(context, index.string_offsets.size() - 1,
    // //     nova::BufferUsage::Storage, nova::BufferFlags::Mapped);

    // auto file_match_mask_buf = nova::Buffer::Create(context, index.file_nodes.size(),
    //     nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    // auto file_match_mask_buf_host = nova::Buffer::Create(context, index.file_nodes.size(),
    //     nova::BufferUsage::Storage, nova::BufferFlags::Mapped);

    // end = steady_clock::now();

    // std::cout << std::format("Vulkan initialized in: {} ms\n",
    //     duration_cast<milliseconds>(end - start).count());

    // ankerl::unordered_dense::set<std::string> results;
    // std::vector<std::string> diff;

    // // Run search on GPU

    // for (uint32_t i = 0; i < 4; ++i) {

    //     start = steady_clock::now();

    //     pool.Reset();

    //     struct search_push_constants_t {
    //         uint64_t string_data_address;
    //         uint64_t string_offsets_address;
    //         uint64_t match_output_address;
    //         uint64_t keywords_address;
    //         uint64_t keyword_offset_address;
    //         uint32_t string_count;
    //         uint32_t keyword_count;
    //     } search_pcs;

    //     search_pcs.string_data_address = string_data_buf.GetAddress();
    //     search_pcs.string_offsets_address = string_offset_buf.GetAddress();
    //     search_pcs.match_output_address = name_match_mask_buf.GetAddress();
    //     search_pcs.keywords_address = keyword_buf.GetAddress();
    //     search_pcs.keyword_offset_address = keyword_offset_buf.GetAddress();
    //     search_pcs.string_count = uint32_t(index.string_offsets.size() - 1);
    //     search_pcs.keyword_count = uint32_t(keywords.size());

    //     auto cmd = pool.Begin();
    //     cmd.BindShaders({ search_shader });
    //     cmd.PushConstants(search_pcs);
    //     constexpr uint32_t workgroup_size = 128;
    //     cmd.Dispatch(Vec3U(
    //         (search_pcs.string_count + workgroup_size - 1) / workgroup_size,
    //         1, 1));
    //     // cmd.Barrier(nova::PipelineStage::Compute, nova::PipelineStage::Transfer);
    //     // cmd.CopyToBuffer(name_match_mask_buf_host, name_match_mask_buf, index.string_offsets.size() - 1);

    //     struct collate_push_constants_t {
    //         uint64_t match_mask_in;
    //         uint64_t nodes;
    //         uint64_t match_mask_out;
    //         uint32_t node_count;
    //         uint32_t target_mask;
    //     } collate_pcs;

    //     collate_pcs.match_mask_in = name_match_mask_buf.GetAddress();
    //     collate_pcs.nodes = file_node_buf.GetAddress();
    //     collate_pcs.match_mask_out = file_match_mask_buf.GetAddress();
    //     collate_pcs.node_count = uint32_t(index.file_nodes.size());
    //     collate_pcs.target_mask = (1 << keywords.size()) - 1;

    //     cmd.BindShaders({ collate_shader });
    //     cmd.PushConstants(collate_pcs);
    //     cmd.Barrier(nova::PipelineStage::Compute, nova::PipelineStage::Compute);
    //     cmd.Dispatch(Vec3U(
    //         (collate_pcs.node_count + workgroup_size - 1) / workgroup_size,
    //         1, 1));
    //     cmd.Barrier(nova::PipelineStage::Compute, nova::PipelineStage::Transfer);
    //     cmd.CopyToBuffer(file_match_mask_buf_host, file_match_mask_buf, index.file_nodes.size());

    //     queue.Submit({cmd}, {}, {fence});
    //     fence.Wait();

    //     uint32_t file_count = 0;
    //     {
    //         const uint8_t* mask = reinterpret_cast<const uint8_t*>(file_match_mask_buf_host.GetMapped());
    //         const uint32_t s = uint32_t(index.file_nodes.size());
    //         for (uint32_t j = 0; j < s; ++j) {
    //             file_count += mask[j];
    //         }
    //     }

    //     end = steady_clock::now();

    //     if (i > 0) {
    //         std::cout << std::format("GPU found {} files in: {} ms ({} us)\n",
    //             file_count,
    //             duration_cast<milliseconds>(end - start).count(),
    //             duration_cast<microseconds>(end - start).count());
    //     }
    // }

    // file_searcher_t searcher;
    // searcher.init(context, context.GetQueue(nova::QueueFlags::Compute, 0));
    // NOVA_CLEANUP(&) { searcher.destroy(); };
    // searcher.set_index(index);
    // searcher.set_index(index);
    // for (uint32_t i = 0; i < 3; ++i) {
    //     searcher.filter(keywords);
    // }

    // Run search on CPU

    start = steady_clock::now();

#pragma omp parallel for
    for (uint32_t i = 0; i < index.string_offsets.size() - 1; ++i) {
        matches[i] = 0;
    }
    for (uint32_t j = 0; j < keywords.size(); ++j) {
#pragma omp parallel for
        for (uint32_t i = 0; i < index.string_offsets.size() - 1; ++i) {
            if (utf8_case_insensitive_contains(index.get_string(i), keywords[j])) {
                matches[i] |= 1 << j;
            }
        }
    }

    end = steady_clock::now();

    uint32_t match_count = 0;
    for (uint32_t i = 0; i  < index.string_offsets.size() - 1; ++i) {
        if (matches[i] != 0) {
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

    // Check for GPU / CPU differences

    // for (uint32_t i = 0; i < index.string_offsets.size() - 1; ++i) {
    //     if (matches[i] != 0) {
    //         auto filename = std::string(index.get_string(i));
    //         if (!results.contains(filename)) {
    //             diff.emplace_back(filename);
    //         } else {
    //             results.erase(filename);
    //         }
    //     }
    // }

    // if (!results.empty() || !diff.empty()) {
    //     for (auto& on_gpu : results) {
    //         std::cout << std::format("ERROR[gpu only]: {}\n", on_gpu);
    //     }
    //     for (auto& on_host : diff) {
    //         std::cout << std::format("ERROR[cpu only]: {}\n", on_host);
    //     }
    //     return 1;
    // }

    {
        // Find matching file nodes

        uint32_t target_mask = (1 << keywords.size()) - 1;

        std::cout << std::format("Target mask: {:#010b}\n", target_mask);

        start = steady_clock::now();

        uint32_t file_count = 0;
        for (uint32_t i = 0; i < index.file_nodes.size(); ++i) {
            auto file = index.file_nodes[i];
            uint32_t mask = 0;
            for (;;) {
                mask |= matches[file.filename];
                if (mask == target_mask)
                    break;

                if (file.parent == UINT_MAX)
                    break;
                file = index.file_nodes[file.parent];
            }

            if (mask == target_mask) {
                if (file_count < 10) {
                    std::cout << std::format(" - {}\n", index.get_full_path(i));
                }
                file_count++;
            }
        }

        end = steady_clock::now();

        std::cout << std::format("Counted files (CPU) = {}\n", file_count);
        std::cout << std::format("  Elapsed: {} ms\n",
            duration_cast<milliseconds>(end - start).count());
    }

    // String data stats

    uint32_t min_size = UINT_MAX, max_size = 0;
    for (uint32_t i = 0; i < index.string_offsets.size() - 1; ++i) {
        auto size = index.string_offsets[i + 1] - index.string_offsets[i];
        min_size = std::min(min_size, size);
        max_size = std::max(max_size, size);
    }
    std::cout << std::format("String size: Avg = {:.2f}, Min = {}, Max = {}\n", double(index.string_data.size()) / (index.string_offsets.size() - 1), min_size, max_size);

    for (u32 i = 0; i < 100; ++i) {
        std::cout << std::format(" - {}\n", index.get_full_path(i));
    }
}