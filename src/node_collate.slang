#include "shared_types.h"

[vk::push_constant] collate_push_constants_t pc;

[shader("compute")]
[numthreads(128, 1, 1)]
void collate(const uint node_index : SV_DispatchThreadID)
{
    if (node_index >= pc.node_count)
        return;

    file_node_t* file = &pc.nodes[node_index];
    uint mask = 0;

    for (;;) {
        mask |= uint(pc.match_mask_in[file.filename]);
        if (mask == pc.target_mask)
            break;

        if (file.parent == ~0u)
            break;
        file = &pc.nodes[file.parent];
    }

    pc.match_mask_out[node_index] = uint8_t(mask == pc.target_mask);
}
