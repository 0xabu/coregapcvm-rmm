#include <stdio.h>

int main()
{
	printf("RMM stats\n");
	asm volatile("mov x8, #451" ::);
	asm volatile("svc #451"     ::);

	return 0;
}

