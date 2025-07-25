#define _GNU_SOURCE

#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#define KVMIO             0xae
#define KVM_API_VERSION   0x00
#define KVM_DEDICATE_CORE 0x0b

int main(int argc, char *argv[]) {
	int cpu_id;
	int kvm_fd;

	if (argc == 2) {
		cpu_id = strtoul(argv[1], NULL, 0);
	} else {
		cpu_id = sched_getcpu();
		if (cpu_id < 0) {
			printf("Could not retrieve CPU ID\n");
			return 1;
		}
	}

	kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
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
	printf("Dedicating CPU %d\n", cpu_id);
	int ret = ioctl(kvm_fd, _IO(KVMIO, KVM_DEDICATE_CORE), cpu_id);

	if (ret < 0) {
		printf("Errno: %s\n", strerror(errno));
	}
	return ret ? 1 : 0;
}
