NPROCS   ?= $(shell nproc)
BUILDDIR  = build
DEBFLAGS  = -DCMAKE_BUILD_TYPE=DEBUG -DTULIPS_TESTS=ON
RELFLAGS  = -DCMAKE_BUILD_TYPE=RELEASE -DTULIPS_HAS_HW_CHECKSUM=ON -DTULIPS_DISABLE_CHECKSUM_CHECK=ON -DTULIPS_IGNORE_INCOMPATIBLE_HW=OFF
EXTFLAGS ?=

.PHONY: build

default: build

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

debug-all:
	@mkdir -p $(BUILDDIR);											\
	 cd $(BUILDDIR);														\
	 rm -rf *;																	\
	 cmake -GNinja $(DEBFLAGS) $(EXTFLAGS) ..;	\
	 cd ..

debug-lib:
	@mkdir -p $(BUILDDIR);											                  \
	 cd $(BUILDDIR);														                  \
	 rm -rf *;																	                  \
	 cmake -GNinja $(DEBFLAGS) -DTULIPS_TOOLS=OFF $(EXTFLAGS) ..;	\
	 cd ..

release-all:
	@mkdir -p $(BUILDDIR);											\
	 cd $(BUILDDIR);														\
	 rm -rf *;																	\
	 cmake -G Ninja $(RELFLAGS) $(EXTFLAGS) ..;	\
	 cd ..

release-lib:
	@mkdir -p $(BUILDDIR);											                    \
	 cd $(BUILDDIR);														                    \
	 rm -rf *;																	                    \
	 cmake -G Ninja $(RELFLAGS) -DTULIPS_TOOLS=OFF $(EXTFLAGS) ..;	\
	 cd ..

clean:
	@rm -rf $(BUILDDIR)
	@rm -f *.keys *.log *.pcap

