#pragma once
#include <string>
using namespace std::literals;
constexpr std::string_view s_collate_shader_glsl = R"glsl(

#extension GL_EXT_buffer_reference2                     : require
#extension GL_EXT_scalar_block_layout                   : require
#extension GL_EXT_shader_explicit_arithmetic_types_int8 : require

layout(buffer_reference, scalar, buffer_reference_align = 1) buffer match_mask_br
{
    uint8_t mask;
};

layout(buffer_reference, scalar, buffer_reference_align = 4) readonly buffer file_node_br
{
    uint parent;
    uint filename;
};

layout(push_constant, scalar) uniform push_constants_t
{
    match_mask_br match_mask_in;
    file_node_br  nodes;
    match_mask_br match_mask_out;
    uint          node_count;
    uint          target_mask;
};

layout(local_size_x = 128, local_size_y = 1, local_size_z = 1) in;
void main()
{
    const uint node_index = gl_GlobalInvocationID.x;
    if (node_index >= node_count)
        return;

    file_node_br file = nodes[node_index];
    uint mask = 0;

    for (;;) {
        mask |= uint(match_mask_in[file.filename].mask);
        if (mask == target_mask)
            break;

        if (file.parent == ~0u)
            break;
        file = nodes[file.parent];
    }

    match_mask_out[node_index].mask = uint8_t(mask == target_mask);
}

)glsl"sv;