#ifndef __RMM_PERF_H
#define __RMM_PERF_H

enum perf_event_id {
	// Any kind of RMM exit
	PERF_RMM_EXIT,
	// Reason for RMM exit
	PERF_EXIT_SYNC,
	PERF_EXIT_IRQ,
	PERF_EXIT_FIQ,
	PERF_EXIT_PSCI,
	PERF_EXIT_RIPAS_CHANGE,
	PERF_EXIT_HOST_CALL,
	PERF_EXIT_SERROR,
	// Sync VM exits
	PERF_SYNC_WFX,
	PERF_SYNC_HVC,
	PERF_SYNC_SMC,
	PERF_SYNC_SYSREG,
	PERF_SYNC_INST_ABORT,
	PERF_SYNC_DATA_ABORT,
	PERF_SYNC_EC_FPU,
	PERF_SYNC_SVE,
	// Other counters
	PERF_GUEST_TIMER, // This is a sub case of IRQs
	PERF_RMM_TICK,
	// Must go last
	PERF_NB_EVENTS,
};

void perf_record_event(enum perf_event_id event);
void perf_display(void);
void perf_time_exit(void);
void perf_reset(void);
void perf_get(unsigned long *regs);
void perf_record_and_time_event(enum perf_event_id event);
void perf_time_resume(void);
void perf_pmu_init(void);

#endif
