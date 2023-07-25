NPROCS   ?= $(shell nproc)
BUILDDIR  = build
DEBFLAGS  = -DCMAKE_BUILD_TYPE=DEBUG -DTULIPS_TESTS=ON
RELFLAGS  = -DCMAKE_BUILD_TYPE=RELEASE -DTULIPS_HAS_HW_CHECKSUM=ON -DTULIPS_DISABLE_CHECKSUM_CHECK=ON -DTULIPS_DEBUG=ON -DTULIPS_IGNORE_INCOMPATIBLE_HW=OFF
EXTFLAGS ?=

.PHONY: build

default: release

build:
	@[ -e $(BUILDDIR) ] && ninja -C $(BUILDDIR) -j $(NPROCS)

test:
	@[ -e $(BUILDDIR) ] && CTEST_PARALLEL_LEVEL=$(NPROCS) ninja -C $(BUILDDIR) test

format:
	@[ -e $(BUILDDIR) ] && ninja -C $(BUILDDIR) -j $(NPROCS) format

format-check:
	@[ -e $(BUILDDIR) ] && ninja -C $(BUILDDIR) -j $(NPROCS) format-check

tidy:
	@[ -e $(BUILDDIR) ] && ninja -C $(BUILDDIR) -j $(NPROCS) tidy

debug:
	@mkdir -p $(BUILDDIR);											\
	 cd $(BUILDDIR);														\
	 rm -rf *;																	\
	 cmake -GNinja $(DEBFLAGS) $(EXTFLAGS) ..;	\
	 cd ..

release:
	@mkdir -p $(BUILDDIR);											\
	 cd $(BUILDDIR);														\
	 rm -rf *;																	\
	 cmake -G Ninja $(RELFLAGS) $(EXTFLAGS) ..;	\
	 cd ..

release-arp:
	@mkdir -p $(BUILDDIR);																						\
	 cd $(BUILDDIR);																									\
	 rm -rf *;																												\
	 cmake -GNinja $(RELFLAGS) $(EXTFLAGS) -DTULIPS_ENABLE_ARP=ON ..;	\
	 cd ..

release-raw:
	@mkdir -p $(BUILDDIR);																						\
	 cd $(BUILDDIR);																									\
	 rm -rf *;																												\
	 cmake -GNinja $(RELFLAGS) $(EXTFLAGS) -DTULIPS_ENABLE_RAW=ON ..;	\
	 cd ..

clean:
	@rm -rf $(BUILDDIR)

