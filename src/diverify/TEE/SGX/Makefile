ARCH_LIBDIR ?= /lib/x86_64-linux-gnu

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: diverify.manifest diverify.manifest.sgx diverify.sig

diverify.manifest: diverify.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=$(realpath $(shell sh -c "command -v python3")) \
		$< >$@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
diverify.manifest.sgx diverify.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: diverify.manifest
	@M=$$(gramine-sgx-sign --manifest $< --output $<.sgx 2>&1 | tee /dev/stderr | grep -A1 "Measurement:" | tail -1 | tr -d ' '); \
	cd ../../../.. && sed -i "s/\"signer_measurement\": \"[^\"]*\"/\"signer_measurement\": \"$$M\"/" src/diverify/policies/**/*.json && \
	echo "Updated policies with measurement: $$M"

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig