#extension GL_EXT_buffer_reference2                     : require
#extension GL_EXT_scalar_block_layout                   : require
#extension GL_EXT_shader_explicit_arithmetic_types_int8 : require

layout(buffer_reference, scalar, buffer_reference_align = 1) readonly buffer string_data_br
{
    uint8_t character;
};

layout(buffer_reference, scalar, buffer_reference_align = 4) readonly buffer string_offsets_br
{
    uint offset;
};

layout(buffer_reference, scalar, buffer_reference_align = 1) writeonly buffer match_output_br
{
    uint8_t mask;
};

layout(push_constant, scalar) uniform push_constants_t
{
    string_data_br    string_data;
    string_offsets_br string_offsets;
    match_output_br   match_output;
    uint              string_count;
    uint              needle_length;
    uint8_t           needle[32];
};

uint8_t to_lower(uint8_t c) {
    return c + (uint8_t((c >= 65) && (c <= 90)) << 5);
}

bool fuzzy_char_compare(uint value_begin, inout uint index, uint8_t c)
{
    uint8_t n = string_data[value_begin + index].character;
    if (n > 127) {
        index += n < 224 ? 1 : n < 240 ? 2 : 3;
        n = uint8_t(63); // '?'
    } else {
        n = to_lower(n);
    }

    return n == c;
}

layout(local_size_x = 128, local_size_y = 1, local_size_z = 1) in;
void main()
{
    const uint str_index = gl_GlobalInvocationID.x;
    if (str_index >= string_count)
        return;

    const uint value_begin = string_offsets[str_index].offset;
    const uint value_end = string_offsets[str_index + 1].offset;

    const uint value_count = value_end - value_begin;
    const uint str_count = needle_length;

    bool found = false;
    if (str_count > value_count) {
        /* found = false; */
    } else if (str_count == 0) {
        found = true;
    } else {

        const uint8_t first = needle[0];
        const uint max_count = value_count - str_count;

        for (uint i = 0; i <= max_count; ++i) {
            if (!fuzzy_char_compare(value_begin, i, first)) {
                while (++i <= max_count && !fuzzy_char_compare(value_begin, i, first));
            }

            if (i <= max_count) {
                uint j = i + 1;
                const uint true_end = j + str_count - 1;
                const uint end = (value_count > true_end) ? true_end : value_count;
                for (uint k = 1
                    ; j < end && fuzzy_char_compare(value_begin, j, needle[k])
                    ; ++j, ++k);

                if (j == true_end) {
                    found = true;
                    break;
                }
            }
        }
    }

    match_output[str_index].mask = uint8_t(found);
}