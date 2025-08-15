/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright 2025 TF-RMM Contributors.
 */

#ifndef RUN_H
#define RUN_H

struct rec;

/*
 * Function to enter Realm with `regs` pointing to GP Regs to be
 * restored/saved when entering/exiting the Realm. This function
 * returns with the Realm exception code which is populated by
 * Realm_exit() on aarch64.
 */
int run_realm(unsigned long *regs);

/*
 * Configure CPTR_EL2 register to not trap FPU or SVE access for Realm and
 * restore the saved SIMD state from memory to registers.
 */
void rec_simd_enable_restore(struct rec *rec);

#endif /* RUN_H */
