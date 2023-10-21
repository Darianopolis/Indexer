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

layout(buffer_reference, scalar, buffer_reference_align = 1) buffer match_output_br
{
    uint8_t mask;
};

layout(push_constant, scalar) uniform push_constants_t
{
    string_data_br    string_data;
    string_offsets_br string_offsets;
    match_output_br   match_output;
    string_data_br    keywords;
    string_offsets_br keyword_offsets;
    uint              string_count;
    uint              keyword_count;
};

uint8_t ascii_to_lower(uint8_t c)
{
    return c + (uint8_t((c >= 65) && (c <= 90)) << 5);
}

bool utf8_case_insensitive_char_compare(uint value_begin, uint index, uint8_t c, out uint out_index)
{
    uint8_t n = string_data[value_begin + index].character;
    if (n > 127) {
        out_index = index + (n < 224 ? 1 : (n < 240 ? 2 : 3));
        n = uint8_t(63); // '?'
    } else {
        out_index = index;
        n = ascii_to_lower(n);
    }

    return n == c;
}

bool utf8_case_insensitive_contains(uint str_index, uint keyword_index)
{
    const uint value_begin = string_offsets[str_index].offset;
    const uint keyword_begin = keyword_offsets[keyword_index].offset;
    const uint value_count = string_offsets[str_index + 1].offset - value_begin;
    const uint str_count = keyword_offsets[keyword_index + 1].offset - keyword_begin;

    uint out_index;

    if (str_count > value_count)
        return false;

    if (str_count == 0)
        return true;

    const uint8_t first = keywords[keyword_begin].character;
    const uint max_index = value_count - str_count;

    for (uint i = 0; i <= max_index; ++i) {
        if (!utf8_case_insensitive_char_compare(value_begin, i, first, out_index)) {
            i = out_index;
            while (++i <= max_index
                    && !utf8_case_insensitive_char_compare(value_begin, i, first, out_index)) {
                i = out_index;
            }
        } else {
            i = out_index;
        }

        if (i <= max_index) {
            uint j = i + 1;
            const uint true_end = j + str_count - 1;
            const uint end = (value_count > true_end) ? true_end : value_count;
            for (uint k = 1
                    ; j < end
                        && utf8_case_insensitive_char_compare(value_begin, j,
                            keywords[keyword_begin + k].character, out_index)
                    ; ++j, ++k) {
                j = out_index;
            }

            if (j == true_end)
                return true;
        }
    }

    return false;
}

layout(local_size_x = 128, local_size_y = 1, local_size_z = 1) in;
void main()
{
    const uint str_index = gl_GlobalInvocationID.x;
    if (str_index >= string_count)
        return;

    uint mask = 0;

    for (uint i = 0; i < keyword_count; ++i) {
        const bool found = utf8_case_insensitive_contains(str_index, i);
        mask |= uint(found) << i;
    }

    match_output[str_index].mask = uint8_t(mask);
}