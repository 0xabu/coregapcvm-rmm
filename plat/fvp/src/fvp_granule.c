/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <debug.h>
#include <assert.h>
#include <fvp_dram.h>
#include <fvp_private.h>
#include <utils_def.h>

struct fvp_dram_layout fvp_dram;

struct fvp_dram_layout *fvp_get_dram_layout(void)
{
	return &fvp_dram;
}

unsigned long plat_granule_addr_to_idx(unsigned long addr)
{
	if (!GRANULE_ALIGNED(addr)) {
		return UINT64_MAX;
	}

	for (int i = 0; i < fvp_dram.num_banks; i++) {
		if ((addr >= fvp_dram.fvp_bank[i].start_addr) &&
			(addr <= fvp_dram.fvp_bank[i].end_addr)) {
			return ((addr - fvp_dram.fvp_bank[i].start_addr) /
				GRANULE_SIZE) + fvp_dram.idx_bank[i];
		}
	}

	INFO("[RMM] ERROR: could not convert address to granule idx: 0x%lx\n", addr);

	return UINT64_MAX;
}

unsigned long plat_granule_idx_to_addr(unsigned long idx)
{
	unsigned long i = 0;

	assert(idx < fvp_dram.num_granules);

	while (i + 1 < fvp_dram.num_banks && idx < fvp_dram.idx_bank[i+1]) {
		i += 1;
	}

	return fvp_dram.fvp_bank[i].start_addr +
			((idx - fvp_dram.idx_bank[i]) * GRANULE_SIZE);
}
