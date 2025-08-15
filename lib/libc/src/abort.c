/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright 2025 TF-RMM Contributors.
 */

#include <debug.h>

void abort(void)
{
	ERROR("ABORT\n");
	panic();
}
