#
# SPDX-License-Identifier: BSD-3-Clause
# SPDX-FileCopyrightText: Copyright 2025 TF-RMM Contributors.
#

#
# Set the RMM_PLATFORM variable to Cmake cache.
#
set(RMM_PLATFORM "fvp" CACHE STRING "platform")
arm_config_option_override(NAME RMM_TOOLCHAIN DEFAULT "gnu")

#
# Width of the virtual address space for the system.
#
arm_config_option_override(NAME VIRT_ADDR_SPACE_WIDTH DEFAULT 38)

#
# Set RMM_MAX_SIZE for this platform (24MB)
#
arm_config_option_override(NAME RMM_MAX_SIZE DEFAULT 0x01800000)

if (NORMAL_WORLD_RMM)
	arm_config_option_override(NAME GICD_BASE_ADDR DEFAULT 0x8000000)
	add_definitions("-DGICD_BASE_ADDR=0x8000000")
	arm_config_option_override(NAME GICR_BASE_ADDR DEFAULT 0x80a0000)
	add_definitions("-DGICR_BASE_ADDR=0x80a0000")
else()
	arm_config_option_override(NAME GICD_BASE_ADDR DEFAULT 0x2f000000)
	add_definitions("-DGICD_BASE_ADDR=0x2f000000")
	arm_config_option_override(NAME GICR_BASE_ADDR DEFAULT 0x2f100000)
	add_definitions("-DGICR_BASE_ADDR=0x2f100000")
endif()

if (INTERRUPT_DELEGATION)
	add_definitions("-DINTERRUPT_DELEGATION=1")
endif()

if (QEMU)
	add_definitions("-DQEMU=1")
endif()

#
# UART Base address. This must be dynamically discovered in future.
# Use UART3 on the FVP for RMM.
#
arm_config_option_override(NAME RMM_UART_ADDR DEFAULT 0x1c0c0000)

#
# Extra memory regions needed by this platform
#
arm_config_option_override(NAME PLAT_CMN_EXTRA_MMAP_REGIONS DEFAULT 1)

#
# Maximum number of translation tables allocated by the runtime context
# for the translation library.
#
arm_config_option_override(NAME PLAT_CMN_CTX_MAX_XLAT_TABLES DEFAULT 6)

#
# Disable FPU/SIMD usage in RMM. Enabling this option turns on
# DMBEDTLS_SHAXXX_USE_A64_CRYPTO_ONLY in Mbed TLS. To run RMM that was compiled
# this way requires Crypto.so plugin to be present for the FVP. This plugin is
# delivered separate to the FVP, and might not be present in all environments.
#
arm_config_option_override(NAME RMM_FPU_USE_AT_REL2 DEFAULT OFF)

#
# Maximum number of granules supported, enough to cover
# (2GB - 64MB) of DRAM0 and 2GB of DRAM1. We overprovision
# for the case that DT has not catered for the 64 MB carveout.
#
arm_config_option_override(NAME RMM_MAX_GRANULES DEFAULT 0x100000)
