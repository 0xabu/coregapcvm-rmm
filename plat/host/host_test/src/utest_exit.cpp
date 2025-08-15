/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright 2025 TF-RMM Contributors.
 */

#include <CppUTest/TestHarness.h>

extern "C" {

	void utest_exit_fail(char *message)
	{
		FAIL_TEST(message);
	}

	void utest_exit_pass(void)
	{
		TEST_EXIT;
	}

}
