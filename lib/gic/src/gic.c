/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <arch_helpers.h>
#include <assert.h>
#include <cpuid.h>
#include <debug.h>
#include <gic.h>
#include <memory.h>
#include <smc-rmi.h>
#include <stdbool.h>
#include <string.h>
#include <timers.h>

static void write_lr(int index, unsigned long lr);
static unsigned long read_lr(int index);

#define VIRT_AFF_GUARD	(UL(0xffffffffffffffff))

/* The macros below fall through to case (n - 1) */
#define READ_ICH_LR_EL2(n)	{				\
	case n:							\
	gicstate->ich_lr_el2[n] = read_ich_lr##n##_el2();	\
	}

#define WRITE_ICH_LR_EL2(n)	{			\
	case n:						\
	write_ich_lr##n##_el2(gicstate->ich_lr_el2[n]);	\
	}

#define READ_ICH_APR_EL2(n)	{				\
	case n:							\
	gicstate->ich_ap0r_el2[n] = read_ich_ap0r##n##_el2();	\
	gicstate->ich_ap1r_el2[n] = read_ich_ap1r##n##_el2();	\
	}

#define WRITE_ICH_APR_EL2(n)	{				\
	case n:							\
	write_ich_ap0r##n##_el2(gicstate->ich_ap0r_el2[n]);	\
	write_ich_ap1r##n##_el2(gicstate->ich_ap1r_el2[n]);	\
	}

/* GIC virtualization features */
struct gic_virt_feature_s {

	/* Number of implemented List registers, minus 1 */
	unsigned int nr_lrs;

	/*
	 * Number of Interrupt Controller Hyp Active
	 * Priorities Group 0/1 Registers [0..3]
	 */
	unsigned int nr_aprs;

	/* RES0 bits in the Priority field in the LRs */
	unsigned long pri_res0_mask;

	/* Max virtual interrupt identifier */
	unsigned long max_vintid;

	/* Support for extended INTID */
	bool ext_range;
};

static struct gic_virt_feature_s gic_virt_feature;

/*
 * Read supported GIC virtualization features
 * and set configuration variables.
 */
void gic_get_virt_features(void)
{
	/* Interrupt Controller VGIC Type Register */
	unsigned long vtr = read_ich_vtr_el2();

	unsigned long nr_pre_bits;
	unsigned long nr_pri_bits;

	/* Number of implemented List registers, minus 1 */
	gic_virt_feature.nr_lrs = EXTRACT(ICH_VTR_EL2_LIST_REGS, vtr);
	assert(gic_virt_feature.nr_lrs < ICH_MAX_LRS);

	/* Number of virtual preemption bits implemented */
	nr_pre_bits = EXTRACT(ICH_VTR_EL2_PRE_BITS, vtr) + 1U;

	/*
	 * Implementation must implement at least 32 levels
	 * of virtual priority (5 priority bits)
	 */
	assert(nr_pre_bits >= 5UL);

	/*
	 * Number of Interrupt Controller Hyp Active Priorities
	 * Group 0/1 Registers [0..3], minus 1
	 */
	gic_virt_feature.nr_aprs = (1UL << (nr_pre_bits - 5UL)) - 1UL;

	/*
	 * Get max virtual interrupt identifier
	 * Number of virtual interrupt identifier bits supported:
	 * 0b000 : 16 bits
	 * 0b001 : 24 bits
	 */
	gic_virt_feature.max_vintid =
				(EXTRACT(ICH_VTR_EL2_ID_BITS, vtr) == 0UL) ?
				((1UL << 16U) - 1UL) : ((1UL << 24U) - 1UL);

	/* Number of virtual priority bits implemented */
	nr_pri_bits = EXTRACT(ICH_VTR_EL2_PRI_BITS, vtr) + 1UL;

	/* RES0 bits in the Priority field in the LRs */
	gic_virt_feature.pri_res0_mask =
			(1UL << (ICH_LR_PRIORITY_WIDTH - nr_pri_bits)) - 1UL;

	/* Support for extended INTID */
	gic_virt_feature.ext_range = (read_icc_ctrl_el1() &
					ICC_CTLR_EL1_EXT_RANGE_BIT) != 0UL;
	VERBOSE("GIC with%s ExtRange:\n",
		gic_virt_feature.ext_range ? "" : "out");
	VERBOSE(" nr_lrs=%u nr_aprs=%u max_vintid=%lu\n",
		gic_virt_feature.nr_lrs, gic_virt_feature.nr_aprs,
		gic_virt_feature.max_vintid);
	VERBOSE(" nr_pri_bits=%lu pri_res0_mask=0x%lx\n",
		nr_pri_bits, gic_virt_feature.pri_res0_mask);
}

void gic_cpu_state_init(struct gic_cpu_state *gicstate)
{
	(void)memset(gicstate, 0, sizeof(*gicstate));
	gicstate->ich_hcr_el2 =
		ICH_HCR_EL2_EN_BIT |	/* Enable virtual CPU interface */
		ICH_HCR_EL2_VSGIEEOICOUNT_BIT | /* Virtual SGIs not supported */
		ICH_HCR_EL2_DVIM_BIT;	/* Direct-injection not supported */
}

void update_existing_irq(unsigned long irq)
{
	unsigned long id = irq & INT_ID_MASK;
	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		unsigned long lr = read_lr(i);
		if ((lr & INT_ID_MASK) == id) {
			NOTICE("[RMM] Updating %lx to %lx\n", lr, irq | P_INT_ID);
			write_lr(i, irq | P_INT_ID);
			NOTICE("[RMM] Wrote    %lx\n", read_lr(i));
			return;
		}
	}

	NOTICE("[RMM] Could not find IRQ to update\n");
}

void clear_phys_slot(struct gic_cpu_state *gic, int slot_idx,
                            enum irq_origin_enum origin) {
	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		struct irq_origin *slot = &gic->irq_origin[i];
		if (slot->origin == origin && slot->slot == slot_idx) {
			NOTICE("[RMM] Clearing phys slot %d\n", i);
			write_lr(i, 0);
		}
	}
}

void gic_copy_state_from_ns(struct gic_cpu_state *gic,
			    struct rmi_rec_entry *rec_entry)
{
	unsigned int i;

	/* Copy List Registers */
	for (i = 0U; i <= gic_virt_feature.nr_lrs; i++) {
		/* gicstate->ich_lr_el2[i] = rec_entry->gicv3_lrs[i]; */

		unsigned long new = rec_entry->gicv3_lrs[i];
		unsigned long old;
		unsigned long int_id = new & INT_ID_MASK;
		bool is_new = true;
		for (int j = 0; j <= gic_virt_feature.nr_lrs; j++) {
			unsigned long lr = read_lr(j) & (~P_INT_ID);
			struct irq_origin *origin = &gic->irq_origin[j];
			if (new != 0 && (lr & INT_ID_MASK) == int_id && origin->origin == IRQ_ORIGIN_KVM) {
				// NOTE: what if interrupt is inserted but invalid? Do we clear them properly?
				// The interrupt already exists, update backlink
				origin->slot = i;
				is_new = false;
				old = lr;
				break;
			}
		}

		gic->kvm_irq[i].irq = new;
		if (is_new) {
			if (new == 0) {
				gic->kvm_irq[i].state = IRQ_FREE;
			} else {
				// NOTE: what if interrupt is not pending? I assume it can't be active and pending?
				gic->kvm_irq[i].state = IRQ_PENDING;
				gic->need_update = true;
			}
		} else if ((new & (~P_INT_ID)) != old) {
			unsigned long new_status = new >> 62;
			/* NOTICE("[RMM] Update kvm slot %i: 0x%lx -> 0x%lx | %lu -> %lu\n", i, old, new, old >> 62, new_status); */

			if (new_status == 0b11) {
				// NOTE fix that!
				// Pending AND Active, need to refresh already injected interrupt
				/* update_existing_irq(new); */
				gic->kvm_irq[i].state = IRQ_PENDING_AND_ACTIVE;
				gic->need_update = true;
			} else if (new_status == 0b01) {
				gic->kvm_irq[i].state = IRQ_PENDING;
				gic->need_update = true;
			} else if (new_status == 0b10) {
				// We should never get there: and active interrupt can't be new, that's a KVM bug!
				NOTICE("[RMM] Unexpected newly ACTIVE interrupt: 0x%lx != 0x%lx\n", new, old);
			} else {
				gic->kvm_irq[i].state = IRQ_FREE;
				/* clear_phys_slot(gicstate, i, IRQ_ORIGIN_KVM); */
			}
		}
	}

	/* Get bits from NS hypervisor */
	gic->ich_hcr_el2 &= ~ICH_HCR_EL2_NS_MASK;
	gic->ich_hcr_el2 |= rec_entry->gicv3_hcr & ICH_HCR_EL2_NS_MASK;
}

void gic_copy_state_to_ns(struct gic_cpu_state *gicstate,
			  struct rmi_rec_exit *rec_exit)
{
	unsigned int i;

	/* Copy List Registers */
	for (i = 0U; i <= gic_virt_feature.nr_lrs; i++) {
		rec_exit->gicv3_lrs[i] = gicstate->kvm_irq[i].irq;
	}

	rec_exit->gicv3_misr = gicstate->ich_misr_el2;
	rec_exit->gicv3_vmcr = gicstate->ich_vmcr_el2;
	rec_exit->gicv3_hcr = gicstate->ich_hcr_el2 &
		(ICH_HCR_EL2_EOI_COUNT_MASK | ICH_HCR_EL2_NS_MASK);
}

static bool is_valid_vintid(unsigned long intid)
{
	/* Check for INTID [0..1019] and [8192..] */
	if (((intid) <= MAX_SPI_ID) ||
	   (((intid) >= MIN_LPI_ID) && ((intid) <= gic_virt_feature.max_vintid))) {
		return true;
	}

	/*
	 * If extended INTID range sopported, check for
	 * Extended PPI [1056..1119] and Extended SPI [4096..5119]
	 */
	return (gic_virt_feature.ext_range ?
		((((intid) >= MIN_EPPI_ID) && ((intid) <= MAX_EPPI_ID)) ||
		 (((intid) >= MIN_ESPI_ID) && ((intid) <= MAX_ESPI_ID))) :
		false);
}

bool gic_validate_state(struct gic_cpu_state *gicstate)
{
	unsigned int i, j;

	for (i = 0U; i <= gic_virt_feature.nr_lrs; i++) {
		unsigned long lr = gicstate->kvm_irq[i].irq; // TODO: modify that
		unsigned long intid = EXTRACT(ICH_LR_VINTID, lr);

		if ((lr & ICH_LR_STATE_MASK) == ICH_LR_STATE_INVALID) {
			continue;
		}

		/* The RMM Specification imposes the constraint that HW == '0' */
		if ((EXTRACT_BIT(ICH_LR_HW, lr) != 0UL) ||
		    /* Check RES0 bits in the Priority field */
		   ((EXTRACT(ICH_LR_PRIORITY, lr) &
			gic_virt_feature.pri_res0_mask) != 0UL) ||
		    /* Only the EOI bit in the pINTID is allowed to be set */
		   ((lr & ICH_LR_PINTID_MASK & ~ICH_LR_EOI_BIT) != 0UL) ||
		    /* Check if vINTID is in the valid range */
		   !is_valid_vintid(intid)) {
			return false;
		}

		/*
		 * Behavior is UNPREDICTABLE if two or more List Registers
		 * specify the same vINTID.
		 */
		for (j = i + 1U; j <= gic_virt_feature.nr_lrs; j++) {
			unsigned long _lr = gicstate->kvm_irq[j].irq;
			unsigned long _intid = EXTRACT(ICH_LR_VINTID, _lr);

			if ((_lr & ICH_LR_STATE_MASK) == ICH_LR_STATE_INVALID) {
				continue;
			}

			if (intid == _intid) {
				return false;
			}
		}
	}

	return true;
}

/* Save ICH_LR<n>_EL2 registers [n...0] */
static void read_lrs(struct gic_cpu_state *gicstate)
{
	switch (gic_virt_feature.nr_lrs) {
	READ_ICH_LR_EL2(15);
	READ_ICH_LR_EL2(14);
	READ_ICH_LR_EL2(13);
	READ_ICH_LR_EL2(12);
	READ_ICH_LR_EL2(11);
	READ_ICH_LR_EL2(10);
	READ_ICH_LR_EL2(9);
	READ_ICH_LR_EL2(8);
	READ_ICH_LR_EL2(7);
	READ_ICH_LR_EL2(6);
	READ_ICH_LR_EL2(5);
	READ_ICH_LR_EL2(4);
	READ_ICH_LR_EL2(3);
	READ_ICH_LR_EL2(2);
	READ_ICH_LR_EL2(1);
	default:
	READ_ICH_LR_EL2(0);
	}
}

static void write_lr(int index, unsigned long lr)
{
	switch (index) {
	case 0:
		asm volatile("msr ich_lr0_el2, %0" :: "r"(lr));
		break;
	case 1:
		asm volatile("msr ich_lr1_el2, %0" :: "r"(lr));
		break;
	case 2:
		asm volatile("msr ich_lr2_el2, %0" :: "r"(lr));
		break;
	case 3:
		asm volatile("msr ich_lr3_el2, %0" :: "r"(lr));
		break;
	case 4:
		asm volatile("msr ich_lr4_el2, %0" :: "r"(lr));
		break;
	case 5:
		asm volatile("msr ich_lr5_el2, %0" :: "r"(lr));
		break;
	case 6:
		asm volatile("msr ich_lr6_el2, %0" :: "r"(lr));
		break;
	case 7:
		asm volatile("msr ich_lr7_el2, %0" :: "r"(lr));
		break;
	case 8:
		asm volatile("msr ich_lr8_el2, %0" :: "r"(lr));
		break;
	case 9:
		asm volatile("msr ich_lr9_el2, %0" :: "r"(lr));
		break;
	case 10:
		asm volatile("msr ich_lr10_el2, %0" :: "r"(lr));
		break;
	case 11:
		asm volatile("msr ich_lr11_el2, %0" :: "r"(lr));
		break;
	case 12:
		asm volatile("msr ich_lr12_el2, %0" :: "r"(lr));
		break;
	case 13:
		asm volatile("msr ich_lr13_el2, %0" :: "r"(lr));
		break;
	case 14:
		asm volatile("msr ich_lr14_el2, %0" :: "r"(lr));
		break;
	case 15:
		asm volatile("msr ich_lr15_el2, %0" :: "r"(lr));
		break;
	}
}

static unsigned long read_lr(int index)
{
	unsigned long lr;
	switch (index) {
	case 0:
		asm volatile("mrs %0, ich_lr0_el2" : "=r"(lr));
		break;
	case 1:
		asm volatile("mrs %0, ich_lr1_el2" : "=r"(lr));
		break;
	case 2:
		asm volatile("mrs %0, ich_lr2_el2" : "=r"(lr));
		break;
	case 3:
		asm volatile("mrs %0, ich_lr3_el2" : "=r"(lr));
		break;
	case 4:
		asm volatile("mrs %0, ich_lr4_el2" : "=r"(lr));
		break;
	case 5:
		asm volatile("mrs %0, ich_lr5_el2" : "=r"(lr));
		break;
	case 6:
		asm volatile("mrs %0, ich_lr6_el2" : "=r"(lr));
		break;
	case 7:
		asm volatile("mrs %0, ich_lr7_el2" : "=r"(lr));
		break;
	case 8:
		asm volatile("mrs %0, ich_lr8_el2" : "=r"(lr));
		break;
	case 9:
		asm volatile("mrs %0, ich_lr9_el2" : "=r"(lr));
		break;
	case 10:
		asm volatile("mrs %0, ich_lr10_el2" : "=r"(lr));
		break;
	case 11:
		asm volatile("mrs %0, ich_lr11_el2" : "=r"(lr));
		break;
	case 12:
		asm volatile("mrs %0, ich_lr12_el2" : "=r"(lr));
		break;
	case 13:
		asm volatile("mrs %0, ich_lr13_el2" : "=r"(lr));
		break;
	case 14:
		asm volatile("mrs %0, ich_lr14_el2" : "=r"(lr));
		break;
	case 15:
		asm volatile("mrs %0, ich_lr15_el2" : "=r"(lr));
		break;
	default:
		lr = 0;
	}

	return lr;
}

void clear_maintenance_irq(void) {
	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		unsigned long lr = read_lr(i);
		if (((lr >> 62) == 0) && ((lr & P_INT_ID) != 0)) {
			// Clear pending interrupt
			write_lr(i, lr & (~P_INT_ID));
		}
	}
}

void inject_guest_timer_irq(struct gic_cpu_state *gic)
{
	unsigned long cntv_ctl = read_cntv_ctl_el02();
	unsigned long cntpct = read_cntpct_el0();
	unsigned long cval = read_cntv_cval_el02();

	if ((cntv_ctl & 0b001) != 0 && cntpct >= cval) {
		// Inject timer interrupt
		push_rmm_irq(gic, VTIMER_IRQ);
	}
}

/* Save ICH_AP0R<n>_EL2 and ICH_AP1R<n>_EL2 registers [n...0] */
static void read_aprs(struct gic_cpu_state *gicstate)
{
	switch (gic_virt_feature.nr_aprs) {
	READ_ICH_APR_EL2(3);
	READ_ICH_APR_EL2(2);
	READ_ICH_APR_EL2(1);
	default:
	READ_ICH_APR_EL2(0);
	}
}

/* Restore ICH_AP0R<n>_EL2 and ICH_AP1R<n>_EL2 registers [n...0] */
static void write_aprs(struct gic_cpu_state *gicstate)
{
	switch (gic_virt_feature.nr_aprs) {
	WRITE_ICH_APR_EL2(3);
	WRITE_ICH_APR_EL2(2);
	WRITE_ICH_APR_EL2(1);
	default:
	WRITE_ICH_APR_EL2(0);
	}
}

void gic_clear_state(struct gic_cpu_state *gicstate) {
	for (int i = 0; i < NR_IRQ_SLOT; i++) {
		gicstate->rmm_irq[i].irq = 0;
		gicstate->rmm_irq[i].state = IRQ_FREE;
		gicstate->kvm_irq[i].irq = 0;
		gicstate->kvm_irq[i].state = IRQ_FREE;
	}

	for (int i = 0; i <= gic_virt_feature.nr_lrs; i ++) {
		write_lr(i, 0);
	}
}

void gic_restore_state(struct gic_cpu_state *gicstate)
{
	// Synchronize IRQ state
	gicstate->need_update = true;

	write_aprs(gicstate);
	write_ich_vmcr_el2(gicstate->ich_vmcr_el2);
	write_ich_hcr_el2(gicstate->ich_hcr_el2);
}

void gic_save_state(struct gic_cpu_state *gicstate)
{
	read_aprs(gicstate);
	read_lrs(gicstate);

	/* Save the status, including MISR */
	gicstate->ich_vmcr_el2 = read_ich_vmcr_el2();
	gicstate->ich_hcr_el2 = read_ich_hcr_el2();
	gicstate->ich_misr_el2 = read_ich_misr_el2();

	/* On REC exit, set ICH_HCR_EL2.En == '0' */
	write_ich_hcr_el2(gicstate->ich_hcr_el2 & ~ICH_HCR_EL2_EN_BIT);
}

static unsigned int get_pending_int(void)
{
	unsigned long int_id;
	asm volatile("mrs %0, icc_iar1_el1" : "=r"(int_id));
	/* asm volatile("mrs %0, icc_hppir1_el1" : "=r"(int_id)); */
	dsb(ish);
	isb();
	return int_id;
}

static void acknowledge_pending_int(unsigned long int_id)
{
	asm volatile("msr icc_eoir1_el1, %0" :: "r"(int_id));
	asm volatile("msr icc_dir_el1, %0" :: "r"(int_id));
	dsb(ish);
}

unsigned long get_running_priority(void)
{
	unsigned long prio;
	asm volatile("mrs %0, icc_rpr_el1" : "=r"(prio));
	return prio & 0xff;
}

void push_rmm_irq(struct gic_cpu_state *gic, unsigned long irq)
{
	unsigned long int_id = irq & INT_ID_MASK;

	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		unsigned long irq = gic->rmm_irq[i].irq;
		if ((irq & INT_ID_MASK) == int_id && (irq >> 62) != 0) {
			// Already in the queue
			return;
		}
	}

	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		if ((gic->rmm_irq[i].irq >> 62) == 0) {
			gic->rmm_irq[i].irq = irq;
			gic->rmm_irq[i].state = IRQ_PENDING;
			gic->need_update = true;
			return;
		}
	}

	NOTICE("[RMM] Dropping RMM IRQ\n");
}

bool irq_is_already_injected(unsigned long irq)
{
	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		unsigned long lr = read_lr(i);
		if ((lr >> 62) != 0 && (lr & INT_ID_MASK) == (irq & INT_ID_MASK)) {
			return true;
		}
	}

	return false;
}

static int find_pending_slot(struct irq_slot* slots)
{
	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		if (slots[i].state == IRQ_PENDING) {
			if (!irq_is_already_injected(slots[i].irq)) {
				return i;
			}
		}
	}

	return -1;
}

void update_irq(struct gic_cpu_state *gic)
{
	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		unsigned long lr = read_lr(i);
		enum irq_origin_enum origin = gic->irq_origin[i].origin;

		if (origin != IRQ_ORIGIN_INVALID) {
			// Synchronize slot
			int slot_idx = gic->irq_origin[i].slot;
			struct irq_slot *slot;

			switch (origin) {
				case IRQ_ORIGIN_KVM:
					slot = &gic->kvm_irq[slot_idx];
					break;
				case IRQ_ORIGIN_RMM:
#ifndef INTERRUPT_DELEGATION
					ERROR("[RMM] Unexpected RMM-injected IRQ\n");
#endif
					slot = &gic->rmm_irq[slot_idx];
					if (lr != 0 && (lr >> 62) == 0) {
						lr = 0;
						write_lr(i, 0);
					}
					break;
				default:
					NOTICE("[RMM] ERROR: invalid origin\n");
					continue;
			}

			if (slot->state == IRQ_PENDING_AND_ACTIVE) {
				// Set as pending and active
				lr = lr | (UL(0b11) << 62);
				write_lr(i, lr);
				slot->state = IRQ_INJECTED;
				/* NOTICE("[RMM] Injecting Pending & Active\n"); */
			}

			if (slot->state == IRQ_INJECTED && (lr & (~P_INT_ID)) != slot->irq) {
				/* char slot_c = origin == IRQ_ORIGIN_KVM? 'k' : 'r'; */
				/* NOTICE("[RMM] Update IRQ %c%d: 0x%lx -> 0x%lx\n", slot_c, slot_idx, slot->irq, lr & (~P_INT_ID)); */
				slot->irq = lr & (~P_INT_ID);
			} else if ((lr >> 62) == 0) {
				// Collect unused invalid interrupt
				write_lr(i, 0);
				lr = 0;
				gic->irq_origin[i].origin = IRQ_ORIGIN_INVALID;
			}
		}

		if ((lr >> 62) == 0) {
			// Free slot, try to inject
			int pending = find_pending_slot(&gic->kvm_irq[0]);
			if (pending >= 0) {
				unsigned long irq = gic->kvm_irq[pending].irq;
				gic->kvm_irq[pending].state = IRQ_INJECTED;
				gic->irq_origin[i].origin = IRQ_ORIGIN_KVM;
				gic->irq_origin[i].slot = pending;
				/* NOTICE("[RMM] Injecting KVM IRQ p%d-k%d - 0x%lx\n", i, pending, irq); */
				write_lr(i, irq | P_INT_ID);
			} else {
				pending = find_pending_slot(&gic->rmm_irq[0]);
				if (pending >= 0) {
					unsigned long irq = gic->rmm_irq[pending].irq;
					gic->rmm_irq[pending].state = IRQ_INJECTED;
					gic->irq_origin[i].origin = IRQ_ORIGIN_RMM;
					gic->irq_origin[i].slot = pending;
					/* NOTICE("[RMM] Injecting RMM IRQ p%d-r%d - 0x%lx\n", i, pending, irq); */
					write_lr(i, irq | P_INT_ID);
				}
			}
		}
	}
}

#ifdef INTERRUPT_DELEGATION
static unsigned exit_counters[MAX_CPUS];

static bool should_exit_to_kvm(void)
{
	unsigned cpuid = my_cpuid();
	unsigned *counter = &exit_counters[cpuid];

	if (*counter >= 100) { // Infrequent exit, just to ensure
		*counter = 0;
		return true;
	} else {
		*counter += 1;
		return false;
	}
}
#endif

bool handle_irqs(struct gic_cpu_state *gic)
{
	bool exit_to_kvm = false;

	while (true) {
		unsigned long int_id = get_pending_int();
		if (int_id == 1023) {
			break;
		} else if (int_id == 26) {
#ifdef INTERRUPT_DELEGATION
			exit_to_kvm = exit_to_kvm || should_exit_to_kvm();
			inject_guest_timer_irq(gic);
			/* push_rmm_irq(gic, VBLK_IRQ); */
			gic->need_update = true;
#else
			exit_to_kvm = true;
#endif
			reset_timer();
			sync_timer_with_guest();
		} else if (int_id == 25) {
			clear_maintenance_irq();
			gic->need_update = true;
			sync_timer_with_guest();
		} else if (int_id == RMM_IPI_ID) {
			// Woken up by another RMM core
		} else if (int_id == RMM_KICK_ID) {
			// The host wants to trigger an exit
			exit_to_kvm = true;
		} else {
			NOTICE("[RMM] Unexpected interrupt: %lu\n", int_id);
		}
		acknowledge_pending_int(int_id);
	}

	return !exit_to_kvm; // handled
}

void debug_irq(struct gic_cpu_state *gic, char *banner) {
	int banner_first = 1;
	int first = 1;
	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		unsigned long lr = read_lr(i);
		struct irq_origin origin = gic->irq_origin[i];
		if (lr != 0) {
			if (banner_first && banner != NULL) {
				NOTICE("%s", banner);
				banner_first = 0;
			}
			if (first) {
				NOTICE("[RMM] Phys LRs:");
				first = false;
			}
			switch (origin.origin) {
				case IRQ_ORIGIN_KVM:
					NOTICE(" p%d-k%d: %lx |", i, origin.slot, lr);
					break;
				case IRQ_ORIGIN_RMM:
					NOTICE(" p%d-r%d: %lx |", i, origin.slot, lr);
					break;
				default:
					NOTICE(" p%d-p%d: %lx |", i, i, lr);
					break;
			}
		}
	}
	if (!first) {
		NOTICE("\n");
	}

	first = 1;
	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		unsigned long lr = gic->kvm_irq[i].irq;
		if (lr != 0) {
			if (banner_first && banner != NULL) {
				NOTICE("%s", banner);
				banner_first = 0;
			}
			if (first) {
				NOTICE("[RMM] KVM LRs: ");
				first = false;
			}
			switch (gic->kvm_irq[i].state) {
				case IRQ_PENDING:
					NOTICE(" k%d-pd: %lx |", i, lr);
					break;
				case IRQ_INJECTED:
					NOTICE(" k%d-ij: %lx |", i, lr);
					break;
				default:
					NOTICE(" k%d-fr: %lx |", i, lr);
					break;
			}
		}
	}
	if (!first) {
		NOTICE("\n");
	}

	first = 1;
	for (int i = 0; i <= gic_virt_feature.nr_lrs; i++) {
		unsigned long lr = gic->rmm_irq[i].irq;
		if (lr != 0) {
			if (banner_first && banner != NULL) {
				NOTICE("%s", banner);
				banner_first = 0;
			}
			if (first) {
				NOTICE("[RMM] RMM LRs: ");
				first = false;
			}
			switch (gic->rmm_irq[i].state) {
				case IRQ_PENDING:
					NOTICE(" r%d-pd: %lx |", i, lr);
					break;
				case IRQ_INJECTED:
					NOTICE(" r%d-ij: %lx |", i, lr);
					break;
				default:
					NOTICE(" r%d-fr: %lx |", i, lr);
					break;
			}
		}
	}
	if (!first) {
		NOTICE("\n");
	}
}

// ————————————————————————————— IPI Emulation —————————————————————————————— //
// TODO: this code assumes a single VM is running

struct core_affinity {
	struct granule *g_rd;
	unsigned long virt_aff;
	unsigned long phys_aff;
};

struct ipi_request {
	unsigned long ipis[16];
	unsigned long running;
};

static struct core_affinity affinity[MAX_CPUS];
static struct ipi_request requests[MAX_CPUS];

void clear_affinity(struct granule *g_rd)
{
	assert(g_rd != NULL);
	for (int i = 0; i < MAX_CPUS; i++) {
		if (affinity[i].g_rd == g_rd) {
			affinity[i].virt_aff = VIRT_AFF_GUARD;
			affinity[i].phys_aff = 0;
			requests[i].running = false;
			for (int j = 0; j < 16; j++) {
				requests[i].ipis[0] = 0;
			}
		}
	}
}

void gic_enter(unsigned cpuid)
{
	__sca_write64_release(&requests[cpuid].running, true);
}

void gic_exit(unsigned cpuid)
{
	__sca_write64_release(&requests[cpuid].running, false);
}

void register_affinity(struct granule *g_rd, unsigned long virt_aff)
{
	int cpuid = my_cpuid();
	assert(g_rd != NULL);
	affinity[cpuid].g_rd = g_rd;
	affinity[cpuid].virt_aff = virt_aff;
	affinity[cpuid].phys_aff = read_mpidr_el1();
	NOTICE("[RMM] Register virt affinity 0x%lx on core %d\n", virt_aff, cpuid);
}

void send_phys_ipi(unsigned long phys_aff, unsigned irq_id)
{
	unsigned long aff3 = (phys_aff >> 32) & 0xff;
	unsigned long aff2 = (phys_aff >> 16) & 0xff;
	unsigned long aff1 = (phys_aff >>  8) & 0xff;
	unsigned long aff0 = (phys_aff >>  0) & 0xff;
	unsigned long rs = aff0 / 16;
	unsigned long target = aff0 % 16;

	uint64_t icc_sgi = (uint64_t)(irq_id << 24)
		| (aff3 << 48) | (aff2 << 32) | (aff1 << 16)
		| (rs << 44) | (1 << target);

	asm(
	    "msr icc_sgi1r_el1, %0;"
	    :
	    :"r"(icc_sgi)
	);
}

int send_virt_ipi(struct granule *g_rd, unsigned long virt_aff, unsigned irq_id)
{
	assert(irq_id < 16);

	for (int i = 0; i < MAX_CPUS; i++) {
		if (affinity[i].g_rd == g_rd && affinity[i].virt_aff == virt_aff) {
			/* NOTICE("[RMM] Sending ipi %d to core %d\n", irq_id, i); */
			// Register IPI request
			__sca_write64_release(&requests[i].ipis[irq_id], true);

			// Send physical IRQ
			send_phys_ipi(affinity[i].phys_aff, RMM_IPI_ID);

			if (!__sca_read64_acquire(&requests[i].running)) {
				return -1;
			}

			return 0;
		}
	}

	return 0;
}

int send_virt_ipi_to_all(struct granule *g_rd, unsigned irq_id, unsigned sender)
{
	assert(irq_id < 16);

	for (int i = 0; i < MAX_CPUS; i++) {
		if (i == sender)
			continue; // Skip self
		if (affinity[i].g_rd == g_rd && affinity[i].virt_aff != VIRT_AFF_GUARD) {
			__sca_write64_release(&requests[i].ipis[irq_id], true);

			// Send physical IRQ
			send_phys_ipi(affinity[i].phys_aff, RMM_IPI_ID);

			if (!__sca_read64_acquire(&requests[i].running)) {
				return -1;
			}
		}
	}

	return 0;
}

void insert_pending_ipi(struct gic_cpu_state *gic)
{
	int cpuid = my_cpuid();
	for (int i = 0; i < 16; i++) {
		if (__sca_read64_acquire(&requests[cpuid].ipis[i])) {
			__sca_write64_release(&requests[cpuid].ipis[i], false);
			push_rmm_irq(gic, VIPI_IRQ | i);
			gic->need_update = true;
			/* NOTICE("[RMM] Core %d got IPI %d\n", cpuid, i); */
		}
	}
}

