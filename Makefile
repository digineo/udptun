VERSION := 1.0.0
DEB     := digineo-udptun_$(VERSION)_amd64.deb
REMOTE  := root@vpntest.openspot.net

$(DEB): kmod/*
	nfpm pkg -p deb

# Deployment auf den server
deploy: $(DEB)
	scp $(DEB) $(REMOTE):
	ssh $(REMOTE) dpkg -i $(DEB)

.PHONY: clean
clean:
	rm -rfv *.deb
