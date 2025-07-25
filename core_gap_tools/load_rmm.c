#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#define KVMIO             0xae
#define KVM_API_VERSION   0x00
#define KVM_DEDICATE_CORE 0x0b
#define KVM_ALLOCATE_RMM  0x0c

int main(int argc, char *argv[]) {
	int cpu_id;
	int kvm_fd;
	int rmm_fd;
	int mem_fd;
	unsigned long rmm_addr, map_size;

	if (argc != 3) {
		printf("Usage:\n%s <RMM Physical Address> <RMM File Path>\n", argv[0]);
		return 1;
	}

	// —————————————————————————— Allocate RMM memory ——————————————————————————— //

	kvm_fd = open("/dev/kvm", O_RDWR);
	if (kvm_fd < 0) {
		printf("Could not open '/dev/kvm':\n%s\n", strerror(errno));
		return 1;
	}

	int version = ioctl(kvm_fd, _IO(KVMIO, KVM_API_VERSION), 0);
	if (version < 0) {
		printf("Could not get API version:\n%s\n", strerror(errno));
		return 1;
	}
	if (version != 12) {
		printf("Unexpected KVM API version: %d\n", version);
		return 1;
	}

	// At this point we can talk to KVM
	rmm_addr = strtoul(argv[1], NULL, 0);
	printf("Setting RMM address to %lx\n", rmm_addr);
	ioctl(kvm_fd, _IO(KVMIO, KVM_ALLOCATE_RMM), rmm_addr);

	// —————————————————————————— Load RMM into memory —————————————————————————— //

	rmm_fd = open(argv[2], O_RDONLY);
	if (rmm_fd < 0) {
		printf("Could not open '/shared/rmm.img'\n%s\n", strerror(errno));
		return 1;
	}

	unsigned long rmm_size = lseek64(rmm_fd, 0, SEEK_END);
	printf("RMM size: 0x%lx bytes\n", rmm_size);
	
	char *rmm_src = mmap(NULL, rmm_size, PROT_READ, MAP_PRIVATE, rmm_fd, 0);
	if (rmm_src == MAP_FAILED) {
		printf("Failed to mmap RMM\n%s\n", strerror(errno));
		return 1;
	}

	mem_fd = open("/dev/mem", O_RDWR);
	if (mem_fd < 0) {
		printf("Could not open '/dev/mem':\n%s\n", strerror(errno));
		return 1;
	}

	map_size = rmm_size + (0x1000 - (rmm_size & (0x1000 - 1)));
	printf("Mapping /dev/mem at 0x%lx, with size 0x%lx\n", rmm_addr, map_size);
	char *rmm_dst = mmap(NULL, map_size, PROT_WRITE, MAP_SHARED, mem_fd, rmm_addr);
	if (rmm_dst == MAP_FAILED) {
		printf("Failed to mmap '/dev/mem'\n%s\n", strerror(errno));
		return 1;
	}

#if 0
	long offset = lseek64(mem_fd, rmm_addr, SEEK_SET);
	if (offset != rmm_addr) {
		printf("Seek failled for RMM memory location\n");
		return 1;
	}
#endif

	printf("memcpy(%p, %p, %zx)\n", rmm_dst, rmm_src, rmm_size);
	// memcpy(rmm_dst, rmm_src, rmm_size);
	for (size_t i = 0; i < rmm_size; i++)
		rmm_dst[i] = rmm_src[i];

	printf("Done loading RMM in memory\n");

	return 0;
}
