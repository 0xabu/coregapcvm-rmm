TARGETS=load_rmm dedicate_core set_wait_strat
CC=aarch64-linux-gnu-gcc

.PHONY: all clean

all: $(TARGETS)

%: %.c
	$(CC) $< -o $@ -static

clean:
	$(RM) $(TARGETS)
