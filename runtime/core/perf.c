#include "arch.h"
#include <cpuid.h>
#include <arch_helpers.h>
#include <assert.h>
#include <debug.h>
#include <perf.h>
#include <arch_features.h>
#include <string.h>

#define PMCR_RESET (PMCR_EL0_C_BIT | PMCR_EL0_P_BIT | PMCR_EL0_E_BIT)
#define COUNT_EL2 (1 << 27)
#define INST_RETIRED 0x0008
#define LL_CACHE_MISS 0x0033
#define STALL 0x003C

struct stats {
	unsigned long perf_events[PERF_NB_EVENTS];
	unsigned long perf_timing[PERF_NB_EVENTS];
	unsigned long perf_timing_other;
	unsigned long exit_counter;
	unsigned long session_counter;
	unsigned long cycle_counter;
	unsigned long counter_0;
	unsigned long counter_1;
	unsigned long counter_2;
	int exit_event;
};

static struct stats stats[MAX_CPUS];

static void aggregate_stats(struct stats *s)
{
	for (int i = 0; i < MAX_CPUS; i++) {
		for (int j = 0; j < PERF_NB_EVENTS; j++) {
			s->perf_events[j] += stats[i].perf_events[j];
			s->perf_timing[j] += stats[i].perf_timing[j];
		}
		s->perf_timing_other += stats[i].perf_timing_other;
		s->exit_counter += stats[i].exit_counter;
		s->session_counter += stats[i].session_counter;
		s->cycle_counter += stats[i].cycle_counter;
		s->counter_0 += stats[i].counter_0;
		s->counter_1 += stats[i].counter_1;
		s->counter_2 += stats[i].counter_2;
	}
}

void perf_record_event(enum perf_event_id event)
{
	stats[my_cpuid()].perf_events[event] += 1;
}

void perf_record_and_time_event(enum perf_event_id event)
{
	unsigned cpuid = my_cpuid();
	stats[cpuid].perf_events[event] += 1;
	stats[cpuid].exit_event = event;
}

void perf_time_exit()
{
	stats[my_cpuid()].exit_counter = read_cntpct_el0();
}

void perf_time_resume()
{
	unsigned cpuid = my_cpuid();
	struct stats *s = &stats[cpuid];
	unsigned long counter = read_cntpct_el0();
	unsigned long delta;

	if (s->exit_counter == 0) {
		return;
	}

	// Update timings
	delta = counter - s->exit_counter;
	if (s->exit_event >= PERF_NB_EVENTS) {
		s->perf_timing_other += delta;
	} else {
		s->perf_timing[s->exit_event] += delta;
	}

	// Reset global state
	s->exit_counter = 0;
	s->exit_event = PERF_NB_EVENTS;
}

static unsigned long average(struct stats *s, enum perf_event_id event, unsigned long freq)
{
	if (s->perf_events[event] == 0) {
		return 0;
	}

	return (s->perf_timing[event] / s->perf_events[event]) / freq;
}

static unsigned long percent(unsigned long a, unsigned long b)
{
	// Compute rounded percentage
	return (100 * a + (b/2)) / b;
}

static unsigned long percent_event(struct stats *s, enum perf_event_id event, enum perf_event_id total)
{
	unsigned long t = s->perf_events[total];
	unsigned long e = s->perf_events[event];

	return percent(e, t);
}

static unsigned long percent_exit(struct stats *s, enum perf_event_id event)
{
	assert(event >= PERF_EXIT_SYNC);
	assert(event <= PERF_EXIT_SERROR);

	return percent_event(s, event, PERF_RMM_EXIT);
}

static unsigned long sum_range(struct stats *s, enum perf_event_id start, enum perf_event_id end)
{
	unsigned long sum = 0;

	assert(start <= end);

	for (enum perf_event_id id = start; id <= end; id++) {
		sum += s->perf_events[id];
	}
	return sum;
}

static unsigned long sum_range_percent(struct stats *s,
                                       enum perf_event_id start,
                                       enum perf_event_id end,
                                       enum perf_event_id total)
{
	unsigned long sum = sum_range(s, start, end);
	unsigned long t = s->perf_events[total];

	return percent(sum, t);
}

void display_one(struct stats *s, unsigned long freq)
{
	unsigned long freq_ns = freq / 1000000000;
	unsigned long rmm_exits = s->perf_events[PERF_RMM_EXIT];

	INFO("[RMM]   RMM ticks:     %-8ld\n", s->perf_events[PERF_RMM_TICK]);
	INFO("[RMM]   RMM_EXIT:      %-8ld\t\t %-3ld%% of RMM ticks\n", rmm_exits, percent_event(s, PERF_RMM_EXIT, PERF_RMM_TICK));
	INFO("[RMM]     SYNC:        %-8ld\t\t %-3ld%% %lu ns\n", s->perf_events[PERF_EXIT_SYNC], percent_exit(s, PERF_EXIT_SYNC), average(s, PERF_EXIT_SYNC, freq_ns));
	INFO("[RMM]     IRQ:         %-8ld\t\t %-3ld%% %lu ns\n", s->perf_events[PERF_EXIT_IRQ], percent_exit(s, PERF_EXIT_IRQ), average(s, PERF_EXIT_IRQ, freq_ns));
	INFO("[RMM]   Sync ticks:    %-8ld\t\t %-3ld%% of RMM ticks\n",
			sum_range(s, PERF_SYNC_WFX, PERF_SYNC_SVE),
			sum_range_percent(s, PERF_SYNC_WFX, PERF_SYNC_SVE, PERF_RMM_TICK));
	INFO("[RMM]     Sys Regs:    %-8ld\t\t%lu ns\n", s->perf_events[PERF_SYNC_SYSREG], average(s, PERF_SYNC_SYSREG, freq_ns));
	INFO("[RMM]     Data abort:  %-8ld\t\t%lu ns\n", s->perf_events[PERF_SYNC_DATA_ABORT], average(s, PERF_SYNC_DATA_ABORT, freq_ns));
	INFO("[RMM]     EC FPU:      %-8ld\t\t%lu ns\n", s->perf_events[PERF_SYNC_EC_FPU], average(s, PERF_SYNC_EC_FPU, freq_ns));
	INFO("[RMM]   Other ticks:   %lu ns (total)\n", s->perf_timing_other / freq_ns);
}

void perf_display(void)
{
	struct stats s;
	memset(&s, 0, sizeof(s));
	unsigned self = my_cpuid();
	unsigned long freq = read_cntfrq_el0();
	unsigned long freq_ns = freq / 1000000000;
	aggregate_stats(&s);
	/* unsigned long rmm_exits = s.perf_events[PERF_RMM_EXIT]; */
	unsigned long delta_t = read_cntpct_el0() - stats[self].session_counter;
	unsigned long delta_c = read_pmccntr_el0() - stats[self].cycle_counter;
	unsigned long delta_0 = read_pmevcntr0_el0() - stats[self].counter_0;
	unsigned long delta_1 = read_pmevcntr1_el0() - stats[self].counter_1;
	unsigned long delta_2 = read_pmevcntr2_el0() - stats[self].counter_2;
	unsigned long delta_t_sec = delta_t / freq;

	INFO("[RMM] CPU Reporting: %u\n", self);
	INFO("[RMM] Timer frequency:      %lu\n", freq);
	INFO("[RMM] Timer frequency (ns): %lu\n", freq_ns);
	INFO("[RMM] Execution time:       %lu s (%lu ns)\n", delta_t_sec, delta_t / freq_ns);
	INFO("[RMM] Cycle count:          %lu (%lu HZ)\n", delta_c, delta_c / delta_t_sec);
	INFO("[RMM] Instructions retired: %lu (%lu%% cycles)\n", delta_0, percent(delta_0, delta_c));
	INFO("[RMM] Stalls:               %lu\n", delta_1);
	INFO("[RMM] LL cache misses:      %lu\n", delta_2);
	INFO("[RMM] Perf stats:\n");

	for (int i = 0; i < MAX_CPUS; i++) {
		int empty = 1;
		for (int j = 0; j < PERF_NB_EVENTS; j++) {
			if (stats[i].perf_events[j] != 0) {
				empty = 0;
				break;
			}
		}
		if (empty)
			continue;

		INFO("[RMM] # CPU %i\n", i);
		display_one(&stats[i], freq);
	}

	INFO("[RMM] # Total\n");
	display_one(&s, freq);
}

static void reset_one(struct stats *s)
{
	for (int i = 0; i < PERF_NB_EVENTS; i++) {
		s->perf_events[i] = 0;
		s->perf_timing[i] = 0;
	}

	s->exit_event = PERF_NB_EVENTS;
	s->perf_timing_other = 0;
	write_pmcr_el0(PMCR_RESET);
	s->exit_counter = read_cntpct_el0();
	s->session_counter = read_cntpct_el0();
	s->cycle_counter = read_pmccntr_el0();
	s->counter_0 = read_pmevcntr0_el0();
	s->counter_1 = read_pmevcntr1_el0();
	s->counter_2 = read_pmevcntr2_el0();
}

void perf_reset(void)
{
	for (int i = 0; i < MAX_CPUS; i++) {
		reset_one(&stats[i]);
	}
}

void perf_get(unsigned long *regs) {
	unsigned cpuid = my_cpuid();
	unsigned long freq = read_cntfrq_el0();
	unsigned long freq_ns = freq / 1000000000;
	regs[1] = stats[cpuid].perf_events[PERF_RMM_EXIT];
	regs[2] = stats[cpuid].perf_events[PERF_EXIT_IRQ];
	regs[3] = average(&stats[cpuid], PERF_EXIT_IRQ, freq_ns);
}

void perf_pmu_init(void)
{
	unsigned long pmcr = 0;
	unsigned long n_counters = 0;
	write_pmcr_el0(PMCR_RESET);
	pmcr = read_pmcr_el0();
	n_counters = (pmcr >> 11) & 0b11111;
	INFO("[RMM] PMCR: 0x%lx\n", pmcr);
	INFO("[RMM] Number of perf counters: %lu\n", n_counters);

	write_pmevtyper0_el0(COUNT_EL2 | INST_RETIRED);
	write_pmevtyper1_el0(COUNT_EL2 | STALL);
	write_pmevtyper2_el0(COUNT_EL2 | LL_CACHE_MISS);
	INFO("[RMM] Reading PMCCFILTR:  0x%lx\n", read_pmccfiltr_el0());
	write_pmccfiltr_el0(COUNT_EL2);
	INFO("[RMM] Reading PMCCFILTR: 0x%lx\n", read_pmccfiltr_el0());
	INFO("[RMM] Reading PMCNTENSET: 0x%lx\n", read_pmcntenset_el0());
	write_pmcntenset_el0((1 << 31) | 0b0000000111);
	INFO("[RMM] Reading PMCNTENSET: 0x%lx\n", read_pmcntenset_el0());
	INFO("[RMM] Reading counters:   0x%lx\n", read_pmccntr_el0());
}
