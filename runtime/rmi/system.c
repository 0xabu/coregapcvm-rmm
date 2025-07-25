/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */
#include "arch_helpers.h"
#include <assert.h>
#include <buffer.h>
#include <debug.h>
#include <cpuid.h>
#include <granule.h>
#include <gic.h>
#include <smc.h>
#include <smc-handler.h>
#include <smc-rmi.h>
#include <memory.h>
#include <perf.h>

COMPILER_ASSERT(RMI_ABI_VERSION_MAJOR <= 0x7FFF);
COMPILER_ASSERT(RMI_ABI_VERSION_MINOR <= 0xFFFF);

#define RMM_IRQ_ID 7

// Some helpers
#define U64_PTR(ptr) ((uint64_t volatile *)(ptr))
#define U32_PTR(ptr) ((uint32_t volatile *)(ptr))

// If the platform you're running on does not have a simple linear map of GICR
// addresses (like the FVP), it may be necessary to extract the actual addresses
// e.g. from dmesg output on boot, and hardcode them below.
#if 0
#define HAVE_GICR_MAP 1

// A mapping from CPU ID -> GICR address
static const unsigned long gicr_map[] = {
	0xNNNNNNN0000, // GICR for PE ID 0
	0xNNNNNNN0000, // GICR for PE ID 1
	// ...
};
#endif

unsigned long smc_version(void)
{
	return RMI_ABI_VERSION;
}

static void handle_smc(struct rmi_channel *channel)
{
	struct smc_result result = {
		.x = {0, 0, 0, 0, 0}
	};

	/* NOTICE("[RMM] Call on CPU %d, fid: 0x%lx\n", my_cpuid(), channel->x0); */

	// Dispatch command
	handle_ns_smc(
			channel->x0,
			channel->x1,
			channel->x2,
			channel->x3,
			channel->x4,
			channel->x5,
			channel->x6,
			&result);

	// Copy result to the channel
	channel->x0 = result.x[0];
	channel->x1 = result.x[1];
	channel->x2 = result.x[2];
	channel->x3 = result.x[3];
	channel->x4 = result.x[4];

	/* NOTICE("[RMM] Call on CPU %d completed\n", my_cpuid()); */
}

static void handle_hello(struct rmi_channel *channel)
{
	channel->rmm_affinity = read_mpidr_el1();
	NOTICE("[RMM] Hello from core %d\n", my_cpuid());
}

static void handle_cmd(struct rmi_channel *channel)
{
	unsigned long cmd = __sca_read64_acquire(&channel->command);
	unsigned long do_send_ipi;
	unsigned long affinity;

	switch (cmd) {
		case CMD_NOOP:
		case CMD_PENDING:
		case CMD_DONE:
		case CMD_DONE_IPI:
		case CMD_SCHEDULED:
			// No command on the channel
			return;
			break;
		case CMD_PING:
			// Pong
			break;
		case CMD_CALL:
			handle_smc(channel);
			break;
		case CMD_HELLO:
			// Special case used during initialization
			handle_hello(channel);
			__sca_write64_release(&channel->command, CMD_NOOP);
			return;
		default:
			NOTICE("[RMM] Unknown command: 0x%lx\n", cmd);
			break;
	}

	do_send_ipi = channel->ipi;
	affinity = channel->affinity;
	channel->ipi = 0;

	if (do_send_ipi) {
		__sca_write64_release(&channel->command, CMD_DONE_IPI);
		send_phys_ipi(affinity, RMM_IRQ_ID);
	} else {
		__sca_write64_release(&channel->command, CMD_DONE);
	}
}

void configure_sysregs(void)
{
	uint64_t value;

	NOTICE("[RMM] Configure system registers\n");
	asm volatile("mrs %0, hcr_el2" : "=r"(value));
	NOTICE("[RMM] hcr_el2:        0x%lx\n", value);
	asm volatile("mrs %0, spsel" : "=r"(value));
	NOTICE("[RMM] spsel:          0x%lx\n", value);

	// DAIF mask
	asm volatile("mrs %0, daif" : "=r"(value));
	NOTICE("[RMM] daif:           0x%lx\n", value);
	value = value & (~0x80); // Unmask IRQs
	asm volatile("msr daif, %0" :: "r"(value));
	asm volatile("mrs %0, daif" : "=r"(value));
	NOTICE("[RMM] daif:           0x%lx\n", value);

	// Priority mask
	asm volatile("mrs %0, icc_pmr_el1" : "=r"(value));
	NOTICE("[RMM] icc_pmr_el1:    0x%lx\n", value);
	value = 0xff;
	asm volatile("msr icc_pmr_el1, %0" :: "r" (value));
	asm volatile("mrs %0, icc_pmr_el1" : "=r"(value));
	NOTICE("[RMM] icc_pmr_el1:    0x%lx\n", value);
}

void tick(void)
{
	/* uint64_t value; */
	uint64_t freq;

	asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
	NOTICE("Tick frequency: %ldHz", freq);
	asm volatile("msr cnthp_tval_el2, %0" :: "r"(freq));

	while (true) {
		asm volatile("wfi");
		NOTICE("[RMM] Tick\n");
	}
}

void configure_timer(void)
{
	uint64_t value;

	NOTICE("[RMM] Configure timer\n");

	asm volatile("mrs %0, cnthp_ctl_el2" : "=r"(value));
	if (!(value & 0b001)) {
		NOTICE("[RMM] Activate HP timer\n");
		value = 0x1; // Enable
		asm volatile("msr cnthp_ctl_el2, %0" :: "r"(value));
	}

	asm volatile("mrs %0, cnthp_ctl_el2" : "=r"(value));
	NOTICE("[RMM] cnthp_ctl_el2:   0x%lx\n", value);
}

void configure_gic(void)
{
	/* uint64_t gicd_base_address = GICD_BASE_ADDR; */
#ifdef HAVE_GICR_MAP
	unsigned cpuid = my_cpuid();
	assert(cpuid < ARRAY_SIZE(gicr_map));
	uint64_t gicr_base_address = gicr_map[cpuid];
#else
	uint64_t gicr_base_address = GICR_BASE_ADDR + 0x20000 * my_cpuid();
#endif
	uint64_t gicr_sgi_base_address  = gicr_base_address + 0x10000;
	uint8_t *gicr_va;
	uint8_t *gicr_sgi_va;
	uint32_t enabled_int;

	NOTICE("[RMM] Configure GIC\n");

	/* NOTICE("[RMM] GICD address 0x%lx\n", gicd_base_address); */
	NOTICE("[RMM] GICR address 0x%lx\n", gicr_base_address);
	NOTICE("[RMM] SGI address  0x%lx\n", gicr_sgi_base_address);

	NOTICE("[RMM] Mapping GICR\n");
	gicr_va = buffer_map_device_internal(SLOT_REC2, (unsigned long)gicr_base_address);
	if (gicr_va == NULL) {
		NOTICE("[RMM] Failed to map GICR\n");
	}

	uint64_t gicr_typer = *U64_PTR(gicr_va + 0x0008);
	NOTICE("[RMM] GICR_TYPER       0x%08lx\n", gicr_typer);
	NOTICE("[RMM] GICR_TYPER.cpuid 0x%08lx\n", (gicr_typer >> 8) & 0xffff);
	NOTICE("[RMM] GICR_STATUSR     0x%08x\n", *U32_PTR(gicr_va + 0x0010));

	// Cleanup, the GICR can not be accessed after this point
	buffer_unmap_internal((void *)gicr_va);

	NOTICE("[RMM] Mapping the GICR SGI\n");
	gicr_sgi_va = buffer_map_device_internal(SLOT_REC2, (unsigned long)gicr_sgi_base_address);
	if (gicr_sgi_va == NULL) {
		NOTICE("[RMM] Failed to map GICR SGI\n");
	}

	enabled_int = *U32_PTR(gicr_sgi_va + 0x0100);

	NOTICE("[RMM] GICR_ISENABLER0 0x%08x\n", enabled_int);
	NOTICE("[RMM] Configuring GICR SGI\n");

#ifdef NORMAL_WORLD_RMM
	*U32_PTR(gicr_sgi_va + 0x0100) = (1 << 26) | (1 << 25) | (1 << RMM_IPI_ID) | (1 << RMM_KICK_ID);
#else
	*U32_PTR(gicr_sgi_va + 0x0100) =  0xffffffff;
#endif
	NOTICE("[RMM] GICR_ISENABLER0 0x%08x\n", *U32_PTR(gicr_sgi_va + 0x0100));

	buffer_unmap_internal((void *)gicr_sgi_va);
}

unsigned long smc_core_dedicate(unsigned long channel_addr)
{
	struct granule *g_channel;
	struct rmi_channel *channel;

	bool keep_looping = true;

	NOTICE("[RMM] Dedicating core %d\n", my_cpuid());
	NOTICE("[RMM] Channel address 0x%lx\n", channel_addr);

	// Park core if channel is not valid
	if (channel_addr == 0) {
		NOTICE("[RMM] Invalid channel address\n");
		while (true) {
			asm volatile("isb");
		}
	}

	g_channel = find_granule(channel_addr);
	if ((g_channel == NULL) || (g_channel->state != GRANULE_STATE_NS)) {
		NOTICE("[RMM] Invalid channel granule\n");
		return 0;
	}
	channel = buffer_map_internal(SLOT_NS_CHANNEL, granule_addr(g_channel));
	if (channel == NULL) {
		NOTICE("[RMM] Channel could not be mapped\n");
		return 0;
	}

	configure_gic();
	perf_pmu_init();
	/* configure_timer(); */
	/* configure_sysregs(); */

	while (keep_looping) {
		handle_cmd(channel);

		// Use ISB as a spin loop hint, saves a bit of power
		asm volatile("isb");
	}

	return 0;
}
