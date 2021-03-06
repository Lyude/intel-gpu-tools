include Makefile.sources

if HAVE_LIBDRM_NOUVEAU
    TESTS_progs_M += $(NOUVEAU_TESTS_M)
endif

if HAVE_LIBDRM_VC4
    TESTS_progs_M += $(VC4_TESTS_M)
endif

if BUILD_TESTS
test-list.txt: Makefile.sources
	@echo TESTLIST > $@
	@echo ${single_kernel_tests} ${multi_kernel_tests} >> $@
	@echo END TESTLIST >> $@

test-list-full.txt: Makefile.sources
	@echo TESTLIST > $@
	@echo ${single_kernel_tests} ${multi_kernel_tests} ${extra_multi_kernel_tests} >> $@
	@echo END TESTLIST >> $@


noinst_PROGRAMS = \
	$(HANG) \
	$(TESTS_testsuite) \
	$(NULL)

pkglibexec_PROGRAMS = \
	gem_alive \
	gem_stress \
	$(TESTS_progs) \
	$(TESTS_progs_M) \
	$(TESTS_progs_XM) \
	$(NULL)

dist_pkglibexec_SCRIPTS = \
	$(TESTS_scripts) \
	$(TESTS_scripts_M) \
	$(scripts) \
	$(NULL)

dist_pkgdata_DATA = \
	$(IMAGES) \
	$(NULL)

all-local: .gitignore
.gitignore: Makefile.sources
	@echo "$(pkglibexec_PROGRAMS) $(HANG) test-list.txt test-list-full.txt .gitignore" | sed 's/\s\+/\n/g' | sort > $@

pkgdata_DATA = test-list.txt test-list-full.txt

EXTRA_PROGRAMS = $(HANG)
EXTRA_DIST = $(common_files) $(check_SCRIPTS)

CLEANFILES = $(EXTRA_PROGRAMS) test-list.txt test-list-full.txt .gitignore

AM_CFLAGS = $(DRM_CFLAGS) $(CWARNFLAGS) -Wno-unused-result $(DEBUG_CFLAGS)\
	-I$(srcdir)/.. \
	-I$(srcdir)/../lib \
	-include "$(srcdir)/../lib/check-ndebug.h" \
	-DIGT_SRCDIR=\""$(abs_srcdir)"\" \
	-DIGT_DATADIR=\""$(pkgdatadir)"\" \
	$(LIBUNWIND_CFLAGS) $(WERROR_CFLAGS) \
	$(NULL)

LDADD = ../lib/libintel_tools.la $(GLIB_LIBS) $(XMLRPC_LIBS)

AM_CFLAGS += $(CAIRO_CFLAGS) $(LIBUDEV_CFLAGS) $(GLIB_CFLAGS)
AM_LDFLAGS = -Wl,--as-needed

drm_import_export_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
drm_import_export_LDADD = $(LDADD) -lpthread
gem_close_race_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_close_race_LDADD = $(LDADD) -lpthread
gem_ctx_basic_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_ctx_basic_LDADD = $(LDADD) -lpthread
gem_ctx_thrash_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_ctx_thrash_LDADD = $(LDADD) -lpthread
gem_exec_parallel_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_exec_parallel_LDADD = $(LDADD) -lpthread
gem_fence_thrash_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_fence_thrash_LDADD = $(LDADD) -lpthread
gem_fence_upload_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_fence_upload_LDADD = $(LDADD) -lpthread
gem_flink_race_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_flink_race_LDADD = $(LDADD) -lpthread
gem_mmap_gtt_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_mmap_gtt_LDADD = $(LDADD) -lpthread
gem_mmap_wc_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_mmap_wc_LDADD = $(LDADD) -lpthread
gem_sync_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_sync_LDADD = $(LDADD) -lpthread
gem_threaded_access_tiled_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_threaded_access_tiled_LDADD = $(LDADD) -lpthread
gem_tiled_swapping_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_tiled_swapping_LDADD = $(LDADD) -lpthread
prime_self_import_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
prime_self_import_LDADD = $(LDADD) -lpthread
gen7_forcewake_mt_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gen7_forcewake_mt_LDADD = $(LDADD) -lpthread
gem_userptr_blits_CFLAGS = $(AM_CFLAGS) $(THREAD_CFLAGS)
gem_userptr_blits_LDADD = $(LDADD) -lpthread

gem_wait_LDADD = $(LDADD) -lrt
kms_flip_LDADD = $(LDADD) -lrt -lpthread
pm_rc6_residency_LDADD = $(LDADD) -lrt

prime_nv_test_CFLAGS = $(AM_CFLAGS) $(DRM_NOUVEAU_CFLAGS)
prime_nv_test_LDADD = $(LDADD) $(DRM_NOUVEAU_LIBS)
prime_nv_api_CFLAGS = $(AM_CFLAGS) $(DRM_NOUVEAU_CFLAGS)
prime_nv_api_LDADD = $(LDADD) $(DRM_NOUVEAU_LIBS)
prime_nv_pcopy_CFLAGS = $(AM_CFLAGS) $(DRM_NOUVEAU_CFLAGS)
prime_nv_pcopy_LDADD = $(LDADD) $(DRM_NOUVEAU_LIBS)
vc4_create_bo_CFLAGS = $(AM_CFLAGS) $(DRM_VC4_CFLAGS)
vc4_create_bo_LDADD = $(LDADD) $(DRM_VC4_LIBS)
vc4_lookup_fail_CFLAGS = $(AM_CFLAGS) $(DRM_VC4_CFLAGS)
vc4_lookup_fail_LDADD = $(LDADD) $(DRM_VC4_LIBS)
vc4_wait_bo_CFLAGS = $(AM_CFLAGS) $(DRM_VC4_CFLAGS)
vc4_wait_bo_LDADD = $(LDADD) $(DRM_VC4_LIBS)
vc4_wait_seqno_CFLAGS = $(AM_CFLAGS) $(DRM_VC4_CFLAGS)
vc4_wait_seqno_LDADD = $(LDADD) $(DRM_VC4_LIBS)

chamelium_CFLAGS = $(AM_CFLAGS) $(XMLRPC_CFLAGS) $(UDEV_CFLAGS)
chamelium_LDADD = $(LDADD) $(XMLRPC_LIBS) $(UDEV_LIBS)
endif

