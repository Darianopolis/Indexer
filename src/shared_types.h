#pragma once

#ifdef __cplusplus
#include <cstdint>
#endif

struct file_node_t
{
    uint32_t parent;
    uint32_t filename;
};

struct search_push_constants_t
{
    const uint8_t*  string_data;
    const uint32_t* string_offsets;
    const uint8_t*  keywords;
    const uint32_t* keyword_offsets;
    uint8_t*        match_output;
    uint32_t        string_count;
    uint32_t        keyword_count;
};

struct collate_push_constants_t
{
    const uint8_t*     match_mask_in;
    const file_node_t* nodes;
    uint8_t*           match_mask_out;
    uint32_t           node_count;
    uint32_t           target_mask;
};
