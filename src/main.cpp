#include <file_indexer.hpp>
#include <strings.hpp>

#include <nova/rhi/nova_RHI.hpp>
#include <nova/rhi/vulkan/glsl/nova_VulkanGlsl.hpp>

#include <iostream>
#include <format>

using namespace std::literals;

using namespace nova::types;

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

    std::string_view needle;
    if (auto _needle = std::ranges::find(args, "--find"); _needle == args.end()) {
        std::cout << "Missing keyword, use --find\n";
        return 1;
    } else {
        needle = *(_needle + 1);
    }
    std::cout << std::format("Searching for: \"{}\"\n", needle);
    std::vector<uint8_t> matches(index.string_offsets.size() - 1);

    start = steady_clock::now();

    auto context = nova::Context::Create({
        .debug = false,
    });
    auto queue = context.GetQueue(nova::QueueFlags::Compute, 0);
    auto pool = nova::CommandPool::Create(context, queue);
    auto fence = nova::Fence::Create(context);

    auto shader = nova::Shader::Create(context, nova::ShaderStage::Compute, "main",
        nova::glsl::Compile(nova::ShaderStage::Compute, "main", "src/string_search.glsl"));

    auto string_data_buf = nova::Buffer::Create(context, index.string_data.size(),
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    string_data_buf.Set<char>(index.string_data);

    auto string_offset_buf = nova::Buffer::Create(context, index.string_offsets.size() * sizeof(index.string_offsets[0]),
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    string_offset_buf.Set<uint32_t>(index.string_offsets);

    auto match_mask_buf = nova::Buffer::Create(context, index.string_offsets.size() - 1,
        nova::BufferUsage::Storage, nova::BufferFlags::DeviceLocal | nova::BufferFlags::Mapped);
    auto match_mask_buf_host = nova::Buffer::Create(context, index.string_offsets.size() - 1,
        nova::BufferUsage::Storage, nova::BufferFlags::Mapped);

    end = steady_clock::now();

    std::cout << std::format("Vulkan initialized in: {} ms\n",
        duration_cast<milliseconds>(end - start).count());

    for (uint32_t i = 0; i < 3; ++i) {

        start = steady_clock::now();

        pool.Reset();

        struct push_constants_t {
            uint64_t string_data_address;
            uint64_t string_offsets_address;
            uint64_t match_output_address;
            uint32_t string_count;
            uint32_t needle_length;
            char     needle[32];
        } push_constants;

        push_constants.string_data_address = string_data_buf.GetAddress();
        push_constants.string_offsets_address = string_offset_buf.GetAddress();
        push_constants.match_output_address = match_mask_buf.GetAddress();
        push_constants.string_count = u32(index.string_offsets.size() - 1);
        push_constants.needle_length = u32(needle.length());
        std::memcpy(push_constants.needle, needle.data(), needle.length());

        auto cmd = pool.Begin();
        cmd.BindShaders({ shader });
        cmd.PushConstants(push_constants);
        constexpr uint32_t workgroupSize = 128;
        constexpr uint32_t repeats = 1;
        cmd.Dispatch(Vec3U(
            (push_constants.string_count + workgroupSize - 1) / workgroupSize,
            repeats, 1));
        cmd.Barrier(nova::PipelineStage::Compute, nova::PipelineStage::Transfer);
        cmd.CopyToBuffer(match_mask_buf_host, match_mask_buf, index.string_offsets.size() - 1);

        queue.Submit({cmd}, {}, {fence});
        fence.Wait();

        end = steady_clock::now();

        uint32_t match_count = 0;
        for (uint32_t j = 0; j < index.string_offsets.size() - 1; ++j) {
            if (match_mask_buf_host.Get<u8>(j) == 1) {
                match_count++;
            }
        }

        if (i > 0) {
            std::cout << std::format("GPU found {} results in: {} ms ({} us)\n",
                match_count,
                duration_cast<milliseconds>(end - start).count(),
                duration_cast<microseconds>(end - start).count());
        }
    }

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