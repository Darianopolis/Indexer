#include "shared_types.h"

[vk::push_constant] search_push_constants_t pc;

uint8_t ascii_to_lower(uint8_t c)
{
    return c + (uint8_t((c >= 65) && (c <= 90)) << 5);
}

bool utf8_case_insensitive_char_compare(uint32_t value_begin, inout uint32_t index, uint8_t c)
{
    uint8_t n = pc.string_data[value_begin + index];
    if (n > 127) {
        index += (n < 224 ? 1 : (n < 240 ? 2 : 3));
        n = uint8_t(63); // '?'
    } else {
        n = ascii_to_lower(n);
    }

    return n == c;
}

bool utf8_case_insensitive_contains(uint32_t str_index, uint32_t keyword_index)
{
    const uint32_t value_begin = pc.string_offsets[str_index];
    const uint32_t keyword_begin = pc.keyword_offsets[keyword_index];
    const uint32_t value_count = pc.string_offsets[str_index + 1] - value_begin;
    const uint32_t str_count = pc.keyword_offsets[keyword_index + 1] - keyword_begin;

    uint32_t out_index;

    if (str_count > value_count)
        return false;

    if (str_count == 0)
        return true;

    const uint8_t first = pc.keywords[keyword_begin];
    const uint32_t max_index = value_count - str_count;

    for (uint32_t i = 0; i <= max_index; ++i) {
        if (!utf8_case_insensitive_char_compare(value_begin, i, first)) {
            while (++i <= max_index && !utf8_case_insensitive_char_compare(value_begin, i, first));
        } else {
            i = out_index;
        }

        if (i <= max_index) {
            uint32_t j = i + 1;
            const uint32_t true_end = j + str_count - 1;
            const uint32_t end = (value_count > true_end) ? true_end : value_count;
            for (uint32_t k = 1
                    ; j < end && utf8_case_insensitive_char_compare(value_begin, j,pc.keywords[keyword_begin + k])
                    ; ++j, ++k);

            if (j == true_end)
                return true;
        }
    }

    return false;
}

[shader("compute")]
[numthreads(128, 1, 1)]
void search(const uint32_t str_index : SV_DispatchThreadID)
{
    if (str_index >= pc.string_count)
        return;

    uint32_t mask = 0;

    for (uint32_t i = 0; i < pc.keyword_count; ++i) {
        const bool found = utf8_case_insensitive_contains(str_index, i);
        mask |= uint32_t(found) << i;
    }

    pc.match_output[str_index] = uint8_t(mask);
}
