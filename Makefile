DEVICE=eth0

build: bpf.o

bpf.o: bpf.c
	clang -Wall -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c $< -o $@

run: bpf.o
	sudo sysctl net.core.bpf_jit_enable=1
	sudo tc qdisc add dev $(DEVICE) clsact || true
	sudo tc filter add dev $(DEVICE) ingress bpf obj bpf.o verbose
delete:
	sudo tc filter delete dev $(DEVICE) ingress
show:
	sudo tc filter show dev $(DEVICE) ingress

clean:
	rm -f bpf.o
