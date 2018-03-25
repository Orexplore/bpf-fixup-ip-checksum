# apt-get install clang

DEVICE=eth0

build: bpf.o

bpf.o: bpf.c
	clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c $< -o $@

run: bpf.o
	sudo tc qdisc add dev $(DEVICE) clsact
	sudo tc filter add dev $(DEVICE) ingress obj bpf.o verbose
delete:
	sudo tc filter delete dev $(DEVICE) parent ffff:
show:
	sudo tc filter show dev ingress $(DEVICE)
