#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define KVMIO             0xae
#define KVM_API_VERSION   0x00
#define KVM_WAIT_STRAT    0x0e

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Usage:\n%s WAIT_STRATEGY\n", argv[0]);
		return 1;
	}

	// —————————————————————————— Allocate RMM memory ——————————————————————————— //

	int kvm_fd = open("/dev/kvm", O_RDWR);
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
	int strat_id = strtol(argv[1], NULL, 0);
	printf("Setting wait strategy to %d\n", strat_id);
	ioctl(kvm_fd, _IO(KVMIO, KVM_WAIT_STRAT), strat_id); // return value is bogus

	return 0;
}
