/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <arch_helpers.h>
#include <debug.h>
#include <gic.h>
#include <rec.h>
#include <smc-rmi.h>

#define TIMEOUT		UL(0x500000)

/*
 * Check that timer output is asserted:
 * Timer enabled: CNTx_CTL_ENABLE = 1
 * Timer condition is met: CNTx_CTL_ISTATUS = 1
 * Timer interrupt is not masked: CNTx_CTL_IMASK = 0
 */
#define	TIMER_ASSERTED(reg)						\
	(((reg) &							\
	(CNTx_CTL_ENABLE | CNTx_CTL_ISTATUS | CNTx_CTL_IMASK)) ==	\
	(CNTx_CTL_ENABLE | CNTx_CTL_ISTATUS))

void reset_timer(void)
{
	uint64_t timeout = TIMEOUT; // Arbitrary value
	write_cnthp_tval_el2(timeout);

	// Debug
	/* asm volatile("mrs %0, cnthp_tval_el2" : "=r"(timeout)); */
	/* NOTICE("[RMM] CNTHP_TVAL_EL2: %lx\n", timeout); */
}

void sync_timer_with_guest(void)
{
	unsigned long cntv_ctl = read_cntv_ctl_el02();
	long cntpct = read_cntpct_el0();
	long tval = read_cntv_cval_el02() - cntpct;

	if (cntv_ctl & 0b001) {
		// Timer is enabled
		if (tval >= 0 && tval <= TIMEOUT) {
			write_cnthp_tval_el2(tval);
		}
	}
}

void save_timer(struct rec *rec)
{
	rec->htimer = read_cnthp_tval_el2();
}

void restore_timer(struct rec *rec)
{
	if (rec->htimer == 0 || rec->htimer >= 0x500000) {
		reset_timer();
	} else {
		write_cnthp_tval_el2(rec->htimer);
		rec->htimer = 0;
	}
}

/*
 * Check the pending state of the timers.
 *
 * When a timer output is asserted, its interrupt signal should be masked at
 * EL2 when running the Realm to prevent the physical interrupt from
 * continuously exiting the Realm.
 *
 * When a timer output is not asserted, the interrupt signal should be
 * unmasked such that if the timer output becomes asserted again, an exit from
 * the Realm happens due to a physical IRQ and we can inject a virtual
 * interrupt again.
 */
bool check_pending_timers(struct rec *rec)
{
	unsigned long cntv_ctl = read_cntv_ctl_el02();
	unsigned long cntp_ctl = read_cntp_ctl_el02();
	unsigned long cnthctl_old = read_cnthctl_el2();

	if (TIMER_ASSERTED(cntv_ctl)) {
		rec->sysregs.cnthctl_el2 |= CNTHCTL_EL2_CNTVMASK;
	} else {
		rec->sysregs.cnthctl_el2 &= ~CNTHCTL_EL2_CNTVMASK;
	}

	if (TIMER_ASSERTED(cntp_ctl)) {
		rec->sysregs.cnthctl_el2 |= CNTHCTL_EL2_CNTPMASK;
	} else {
		rec->sysregs.cnthctl_el2 &= ~CNTHCTL_EL2_CNTPMASK;
	}

	if (cnthctl_old != rec->sysregs.cnthctl_el2) {
		write_cnthctl_el2(rec->sysregs.cnthctl_el2);
		isb();
	}

	/*
	 * We don't want to run the Realm just to immediately exit due a
	 * physical interrupt caused by one of the timer interrupts not having
	 * been retired from the CPU interface yet. Check that the interrupts
	 * are retired before entering the Realm.
	 */
	while (true) {
		unsigned long hppir = read_icc_hppir1_el1();
		unsigned int intid = EXTRACT(ICC_HPPIR1_EL1_INTID, hppir);

		if (!((((rec->sysregs.cnthctl_el2 & CNTHCTL_EL2_CNTVMASK) != 0UL) &&
			(intid == EL1_VIRT_TIMER_PPI)) ||
		      (((rec->sysregs.cnthctl_el2 & CNTHCTL_EL2_CNTPMASK) != 0UL) &&
			(intid == EL1_PHYS_TIMER_PPI)))) {
			break;
		}
	}

	/*
	 * Check if the timers changed their output status based on
	 * the previously saved timer state at the last Realm exit.
	 */
	return (TIMER_ASSERTED(cntv_ctl) !=
		TIMER_ASSERTED(rec->sysregs.cntv_ctl_el0)) ||
		(TIMER_ASSERTED(cntp_ctl) !=
		 TIMER_ASSERTED(rec->sysregs.cntp_ctl_el0));
}

void report_timer_state_to_ns(struct rmi_rec_exit *rec_exit)
{
	/* Expose Realm EL1 timer state */
#ifdef INTERRUPT_DELEGATION
	// Makes the host belive timers are disabled
	rec_exit->cntv_ctl = 0;
	rec_exit->cntv_cval = 0;
	rec_exit->cntp_ctl = 0;
	rec_exit->cntp_cval = 0;
#else // INTERRUPT_DELEGATION
	rec_exit->cntv_ctl = read_cntv_ctl_el02();
	rec_exit->cntv_cval = read_cntv_cval_el02() - read_cntvoff_el2();

	rec_exit->cntp_ctl = read_cntp_ctl_el02();
# ifdef NORMAL_WORLD_RMM
	rec_exit->cntp_cval = read_cntp_cval_el02();
# else
	rec_exit->cntp_cval = read_cntp_cval_el02() - read_cntpoff_el2();
# endif
#endif // INTERRUPT_DELEGATION
}
