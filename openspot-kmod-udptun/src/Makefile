KVERSION ?= $(shell uname -r)
KERNEL_DIR ?= /lib/modules/$(KVERSION)/build

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
	rm -vf *.deb


###########################################################
# debian packaging

VERSION := 1.0.0
DEB     := digineo-udptun_$(VERSION)_amd64.deb

$(DEB): $({module,xmit,recv}.{h,c})
	nfpm pkg -p deb

deb: $(DEB)
