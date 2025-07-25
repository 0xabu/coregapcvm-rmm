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
#define KVM_SET_PRIO      0x0f

int main(int argc, char *argv[]) {
	int strat;
	int kvm_fd;

	if (argc == 2) {
		strat = strtoul(argv[1], NULL, 0);
	} else {
		printf("Usage: set_prio <STRAT>\n");
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
	printf("Setting priority %d\n", strat);
	int ret = ioctl(kvm_fd, _IO(KVMIO, KVM_SET_PRIO), strat);

	return 0;
}
