SCHED=hls
obj-m += sch_${SCHED}.o

REGISTER_MOD=${SCHED}

all: ${obj-m:.o=.ko}

base:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

${obj-m:.o=.ko}: %.ko: base
	/usr/src/linux-headers-$(shell uname -r)/scripts/sign-file sha256 ~/.ssh/keys/module/sch.priv ~/.ssh/keys/module/sch.der $@

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

unregister:
	sudo tc qdisc del dev lo root || true
	sudo rmmod sch_${REGISTER_MOD} || true

register: sch_${REGISTER_MOD}.ko
	sudo tc qdisc del dev lo root || true
	sudo rmmod sch_${REGISTER_MOD} || true
	sudo insmod ./sch_${REGISTER_MOD}.ko
