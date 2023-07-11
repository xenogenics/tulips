NPROCS   ?= $(shell nproc)
BUILDDIR  = build
DEBFLAGS  = -DCMAKE_BUILD_TYPE=DEBUG -DTULIPS_TESTS=ON
RELFLAGS  = -DCMAKE_BUILD_TYPE=RELEASE -DTULIPS_HAS_HW_CHECKSUM=ON -DTULIPS_DISABLE_CHECKSUM_CHECK=ON -DTULIPS_DEBUG=ON -DTULIPS_IGNORE_INCOMPATIBLE_HW=OFF
EXTFLAGS ?=

.PHONY: build

default: release

build:
	@[ -e $(BUILDDIR) ] && make -s -C $(BUILDDIR) -j $(NPROCS)

test:
	@[ -e $(BUILDDIR) ] && make -s -C $(BUILDDIR) test

debug:
	@mkdir -p $(BUILDDIR);																																	\
	 cd $(BUILDDIR);																																				\
	 rm -rf *;																																							\
	 GTEST_ROOT=$(HOME)/.local TCLAP_ROOT=$(HOME)/.local cmake $(DEBFLAGS) $(EXTFLAGS) ..;	\
	 cd ..

release:
	@mkdir -p $(BUILDDIR);																																	\
	 cd $(BUILDDIR);																																				\
	 rm -rf *;																																							\
	 GTEST_ROOT=$(HOME)/.local TCLAP_ROOT=$(HOME)/.local cmake $(RELFLAGS) $(EXTFLAGS) ..;	\
	 cd ..

release-arp:
	@mkdir -p $(BUILDDIR);																																												\
	 cd $(BUILDDIR);																																															\
	 rm -rf *;																																																		\
	 GTEST_ROOT=$(HOME)/.local TCLAP_ROOT=$(HOME)/.local cmake $(RELFLAGS) $(EXTFLAGS) -DTULIPS_ENABLE_ARP=ON ..;	\
	 cd ..

release-raw:
	@mkdir -p $(BUILDDIR);																																												\
	 cd $(BUILDDIR);																																															\
	 rm -rf *;																																																		\
	 GTEST_ROOT=$(HOME)/.local TCLAP_ROOT=$(HOME)/.local cmake $(RELFLAGS) $(EXTFLAGS) -DTULIPS_ENABLE_RAW=ON ..;	\
	 cd ..

clean:
	@rm -rf $(BUILDDIR)

