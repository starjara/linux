/* Garden : Copying SafeBPF */
#include <linux/bpf.h>
#include <linux/bitmap.h>

#define MAP_BITMAP_SIZE 32

#define IS_MASKING_ENABLED_FOR_MAP(type) ( type == BPF_MAP_TYPE_ARRAY || type == BPF_MAP_TYPE_HASH )

static inline void bpf_sandbox_map_info_init(struct bpf_prog *prog)
{
    if (!prog) return;

    if (!prog->map_info) {
        prog->map_info = kmalloc(sizeof(struct bpf_sandbox_map_jit_info), GFP_KERNEL);
        if (prog->map_info) {
            prog->map_info->map_reg_bitmap = bitmap_zalloc(MAP_BITMAP_SIZE, GFP_KERNEL);
        }
    } else {
        memset(prog->map_info, 0, sizeof(struct bpf_sandbox_map_jit_info));
        
        if (prog->map_info->map_reg_bitmap) {
            bitmap_clear(prog->map_info->map_reg_bitmap, 0, MAP_BITMAP_SIZE);
        } else {
            prog->map_info->map_reg_bitmap = bitmap_zalloc(MAP_BITMAP_SIZE, GFP_KERNEL);
        }
    }
}
static inline bool is_map_reg(const struct bpf_prog *prog, u8 reg)
{

	int bit;
	//pr_info("SafeBPF: [AFTER SET] Current Bitmap Value: 0x%lx\n", 
          //      prog->map_info->map_reg_bitmap[0]);
	for (bit = 0; bit < MAP_BITMAP_SIZE; bit++){
		bit = find_next_bit(prog->map_info->map_reg_bitmap, MAP_BITMAP_SIZE, bit);
		if (bit == reg){
			//pr_info("BPF MAP: bit = %d, reg = %d", bit, reg);
			return true;
		}
	}
	return false;

}

void bpf_sandbox_add_map(struct bpf_map *map);
void bpf_sandbox_delete_map(struct bpf_map *map);
void bpf_sandbox_add_map_lookup(const struct bpf_map_ops *ops);

bool is_active_map(u64 map);
bool is_map_lookup(u64 fn);
