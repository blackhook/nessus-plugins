#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-153.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106740);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15129", "CVE-2017-17712", "CVE-2017-17862", "CVE-2017-17864", "CVE-2017-18017", "CVE-2017-5715", "CVE-2018-1000004", "CVE-2018-5332", "CVE-2018-5333");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-153) (Spectre)");
  script_summary(english:"Check for the openSUSE-2018-153 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.114 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-5715: Systems with microprocessors utilizing
    speculative execution and indirect branch prediction may
    allow unauthorized disclosure of information to an
    attacker with local user access via a side-channel
    analysis (bnc#1068032).

    The previous fix using CPU Microcode has been
    complemented by building the Linux Kernel with return
    trampolines aka 'retpolines'.

  - CVE-2018-5333: In the Linux kernel the rds_cmsg_atomic
    function in net/rds/rdma.c mishandled cases where page
    pinning fails or an invalid address is supplied, leading
    to an rds_atomic_free_op NULL pointer dereference
    (bnc#1075617).

  - CVE-2018-5332: In the Linux kernel the
    rds_message_alloc_sgs() function did not validate a
    value that is used during DMA page allocation, leading
    to a heap-based out-of-bounds write (related to the
    rds_rdma_extra_size function in net/rds/rdma.c)
    (bnc#1075621).

  - CVE-2017-17862: kernel/bpf/verifier.c in the Linux
    kernel ignores unreachable code, even though it would
    still be processed by JIT compilers. This behavior, also
    considered an improper branch-pruning logic issue, could
    possibly be used by local users for denial of service
    (bnc#1073928).

  - CVE-2017-17864: kernel/bpf/verifier.c in the Linux
    kernel mishandled states_equal comparisons between the
    pointer data type and the UNKNOWN_VALUE data type, which
    allowed local users to obtain potentially sensitive
    address information, aka a 'pointer leak (bnc#1073928).

  - CVE-2017-17712: The raw_sendmsg() function in
    net/ipv4/raw.c in the Linux kernel had a race condition
    in inet->hdrincl that lead to uninitialized stack
    pointer usage; this allowed a local user to execute code
    and gain privileges (bnc#1073229 1073230).

  - CVE-2017-15129: A use-after-free vulnerability was found
    in network namespaces code affecting the Linux kernel
    The function get_net_ns_by_id() in
    net/core/net_namespace.c did not check for the
    net::count value after it has found a peer network in
    netns_ids idr, which could lead to double free and
    memory corruption. This vulnerability could allow an
    unprivileged local user to induce kernel memory
    corruption on the system, leading to a crash. Due to the
    nature of the flaw, privilege escalation cannot be fully
    ruled out, although it is thought to be unlikely
    (bnc#1074839).

  - CVE-2017-18017: The tcpmss_mangle_packet function in
    net/netfilter/xt_TCPMSS.c in the Linux kernel allowed
    remote attackers to cause a denial of service
    (use-after-free and memory corruption) or possibly have
    unspecified other impact by leveraging the presence of
    xt_TCPMSS in an iptables action (bnc#1074488).

  - CVE-2018-1000004: In the Linux kernel versions a race
    condition vulnerability existed in the sound system,
    this can lead to a deadlock and denial of service
    condition (bnc#1076017).

The following non-security bugs were fixed :

  - 509: fix printing uninitialized stack memory when OID is
    empty (bsc#1075078).

  - 8021q: fix a memory leak for VLAN 0 device
    (bnc#1012382).

  - acpi / scan: Prefer devices without _HID/_CID for _ADR
    matching (bnc#1012382).

  - af_key: fix buffer overread in parse_exthdrs()
    (bnc#1012382).

  - af_key: fix buffer overread in verify_address_len()
    (bnc#1012382).

  - afs: Adjust mode bits processing (bnc#1012382).

  - afs: Connect up the CB.ProbeUuid (bnc#1012382).

  - afs: Fix afs_kill_pages() (bnc#1012382).

  - afs: Fix missing put_page() (bnc#1012382).

  - afs: Fix page leak in afs_write_begin() (bnc#1012382).

  - afs: Fix the maths in afs_fs_store_data() (bnc#1012382).

  - afs: Flush outstanding writes when an fd is closed
    (bnc#1012382).

  - afs: Migrate vlocation fields to 64-bit (bnc#1012382).

  - afs: Populate and use client modification time
    (bnc#1012382).

  - afs: Populate group ID from vnode status (bnc#1012382).

  - afs: Prevent callback expiry timer overflow
    (bnc#1012382).

  - alpha: fix build failures (bnc#1012382).

  - alsa: aloop: Fix inconsistent format due to incomplete
    rule (bsc#1031717).

  - alsa: aloop: Fix racy hw constraints adjustment
    (bsc#1031717).

  - alsa: aloop: Release cable upon open error path
    (bsc#1031717).

  - alsa: hda - Apply headphone noise quirk for another Dell
    XPS 13 variant (bsc#1031717).

  - alsa: hda - Apply the existing quirk to iMac 14,1
    (bsc#1031717).

  - alsa: pcm: Abort properly at pending signal in OSS
    read/write loops (bsc#1031717).

  - alsa: pcm: Add missing error checks in OSS emulation
    plugin builder (bsc#1031717).

  - alsa: pcm: Allow aborting mutex lock at OSS read/write
    loops (bsc#1031717).

  - alsa: pcm: Remove incorrect snd_BUG_ON() usages
    (bsc#1031717).

  - alsa: pcm: Remove yet superfluous WARN_ON()
    (bsc#1031717).

  - arc: uaccess: dont use 'l' gcc inline asm constraint
    modifier (bnc#1012382).

  - arm64: Add skeleton to harden the branch predictor
    against aliasing attacks (bsc#1068032).

  - arm64: Add trace_hardirqs_off annotation in ret_to_user
    (bsc#1068032).

  - arm64: Branch predictor hardening for Cavium ThunderX2
    (bsc#1068032).

  - arm64/cpufeature: do not use mutex in bringup path
    (bsc#1068032).

  - arm64: cpufeature: Pass capability structure to ->enable
    callback (bsc#1068032).

  - arm64: cputype: Add MIDR values for Cavium ThunderX2
    CPUs (bsc#1068032).

  - arm64: cputype: Add missing MIDR values for Cortex-A72
    and Cortex-A75 (bsc#1068032).

  - arm64: debug: remove unused local_dbg_(enable, disable)
    macros (bsc#1068032).

  - arm64: Define cputype macros for Falkor CPU
    (bsc#1068032).

  - arm64: Disable TTBR0_EL1 during normal kernel execution
    (bsc#1068032).

  - arm64: Do not force KPTI for CPUs that are not
    vulnerable (bsc#1076187).

  - arm64: do not pull uaccess.h into *.S (bsc#1068032).

  - arm64: Enable CONFIG_ARM64_SW_TTBR0_PAN (bsc#1068032).

  - arm64: entry: Add exception trampoline page for
    exceptions from EL0 (bsc#1068032).

  - arm64: entry: Add fake CPU feature for unmapping the
    kernel at EL0 (bsc#1068032).

  - arm64: entry: Explicitly pass exception level to
    kernel_ventry macro (bsc#1068032).

  - arm64: entry: Hook up entry trampoline to exception
    vectors (bsc#1068032).

  - arm64: entry: remove pointless SPSR mode check
    (bsc#1068032).

  - arm64: entry.S convert el0_sync (bsc#1068032).

  - arm64: entry.S: convert el1_sync (bsc#1068032).

  - arm64: entry.S: convert elX_irq (bsc#1068032).

  - arm64: entry.S: move SError handling into a C function
    for future expansion (bsc#1068032).

  - arm64: entry.S: Remove disable_dbg (bsc#1068032).

  - arm64: erratum: Work around Falkor erratum #E1003 in
    trampoline code (bsc#1068032).

  - arm64: explicitly mask all exceptions (bsc#1068032).

  - arm64: factor out entry stack manipulation
    (bsc#1068032).

  - arm64: factor out PAGE_* and CONT_* definitions
    (bsc#1068032).

  - arm64: Factor out PAN enabling/disabling into separate
    uaccess_* macros (bsc#1068032).

  - arm64: Factor out TTBR0_EL1 post-update workaround into
    a specific asm macro (bsc#1068032).

  - arm64: factor work_pending state machine to C
    (bsc#1068032).

  - arm64: fpsimd: Prevent registers leaking from dead tasks
    (bnc#1012382).

  - arm64: Handle el1 synchronous instruction aborts cleanly
    (bsc#1068032).

  - arm64: Handle faults caused by inadvertent user access
    with PAN enabled (bsc#1068032).

  - arm64: head.S: get rid of x25 and x26 with 'global'
    scope (bsc#1068032).

  - arm64: Implement branch predictor hardening for affected
    Cortex-A CPUs (bsc#1068032).

  - arm64: Implement branch predictor hardening for Falkor
    (bsc#1068032).

  - arm64: Initialise high_memory global variable earlier
    (bnc#1012382).

  - arm64: introduce an order for exceptions (bsc#1068032).

  - arm64: introduce mov_q macro to move a constant into a
    64-bit register (bsc#1068032).

  - arm64: Introduce uaccess_(disable,enable) functionality
    based on TTBR0_EL1 (bsc#1068032).

  - arm64: kaslr: Put kernel vectors address in separate
    data page (bsc#1068032).

  - arm64: Kconfig: Add CONFIG_UNMAP_KERNEL_AT_EL0
    (bsc#1068032).

  - arm64: Kconfig: Reword UNMAP_KERNEL_AT_EL0 kconfig entry
    (bsc#1068032).

  - arm64: kill ESR_LNX_EXEC (bsc#1068032).

  - arm64: kpti: Fix the interaction between ASID switching
    and software PAN (bsc#1068032).

  - arm64: KVM: Fix SMCCC handling of unimplemented SMC/HVC
    calls (bsc#1076232).

  - arm64: KVM: fix VTTBR_BADDR_MASK BUG_ON off-by-one
    (bnc#1012382).

  - arm64: KVM: Make PSCI_VERSION a fast path (bsc#1068032).

  - arm64: KVM: Use per-CPU vector when BP hardening is
    enabled (bsc#1068032).

  - arm64: Mask all exceptions during kernel_exit
    (bsc#1068032).

  - arm64: mm: Add arm64_kernel_unmapped_at_el0 helper
    (bsc#1068032).

  - arm64: mm: Allocate ASIDs in pairs (bsc#1068032).

  - arm64: mm: Fix and re-enable ARM64_SW_TTBR0_PAN
    (bsc#1068032).

  - arm64: mm: hardcode rodata=true (bsc#1068032).

  - arm64: mm: Introduce TTBR_ASID_MASK for getting at the
    ASID in the TTBR (bsc#1068032).

  - arm64: mm: Invalidate both kernel and user ASIDs when
    performing TLBI (bsc#1068032).

  - arm64: mm: Map entry trampoline into trampoline and
    kernel page tables (bsc#1068032).

  - arm64: mm: Move ASID from TTBR0 to TTBR1 (bsc#1068032).

  - arm64: mm: Remove pre_ttbr0_update_workaround for Falkor
    erratum #E1003 (bsc#1068032).

  - arm64: mm: Rename post_ttbr0_update_workaround
    (bsc#1068032).

  - arm64: mm: Temporarily disable ARM64_SW_TTBR0_PAN
    (bsc#1068032).

  - arm64: mm: Use non-global mappings for kernel space
    (bsc#1068032).

  - arm64: Move BP hardening to check_and_switch_context
    (bsc#1068032).

  - arm64: Move post_ttbr_update_workaround to C code
    (bsc#1068032).

  - arm64: Move the async/fiq helpers to explicitly set
    process context flags (bsc#1068032).

  - arm64: SW PAN: Point saved ttbr0 at the zero page when
    switching to init_mm (bsc#1068032).

  - arm64: SW PAN: Update saved ttbr0 value on
    enter_lazy_tlb (bsc#1068032).

  - arm64: swp emulation: bound LL/SC retries before
    rescheduling (bsc#1068032).

  - arm64: sysreg: Fix unprotected macro argmuent in
    write_sysreg (bsc#1068032).

  - arm64: Take into account ID_AA64PFR0_EL1.CSV3
    (bsc#1068032).

  - arm64: thunderx2: remove branch predictor hardening
    References: bsc#1076232 This causes undefined
    instruction abort on the smc call from guest kernel.
    Disable until kvm is fixed.

  - arm64: tls: Avoid unconditional zeroing of tpidrro_el0
    for native tasks (bsc#1068032).

  - arm64: Turn on KPTI only on CPUs that need it
    (bsc#1076187).

  - arm64: use alternative auto-nop (bsc#1068032).

  - arm64: use RET instruction for exiting the trampoline
    (bsc#1068032).

  - arm64: xen: Enable user access before a privcmd hvc call
    (bsc#1068032).

  - arm/arm64: KVM: Make default HYP mappings non-excutable
    (bsc#1068032).

  - arm: avoid faulting on qemu (bnc#1012382).

  - arm: BUG if jumping to usermode address in kernel mode
    (bnc#1012382).

  - arm-ccn: perf: Prevent module unload while PMU is in use
    (bnc#1012382).

  - arm: dma-mapping: disallow dma_get_sgtable() for
    non-kernel managed memory (bnc#1012382).

  - arm: dts: am335x-evmsk: adjust mmc2 param to allow
    suspend (bnc#1012382).

  - arm: dts: kirkwood: fix pin-muxing of MPP7 on OpenBlocks
    A7 (bnc#1012382).

  - arm: dts: ti: fix PCI bus dtc warnings (bnc#1012382).

  - arm: kprobes: Align stack to 8-bytes in test code
    (bnc#1012382).

  - arm: kprobes: Fix the return address of multiple
    kretprobes (bnc#1012382).

  - arm: KVM: Fix VTTBR_BADDR_MASK BUG_ON off-by-one
    (bnc#1012382).

  - arm: OMAP1: DMA: Correct the number of logical channels
    (bnc#1012382).

  - arm: OMAP2+: Fix device node reference counts
    (bnc#1012382).

  - arm: OMAP2+: gpmc-onenand: propagate error on
    initialization failure (bnc#1012382).

  - arm: OMAP2+: Release device node after it is no longer
    needed (bnc#1012382).

  - asm-prototypes: Clear any CPP defines before declaring
    the functions (git-fixes).

  - asn.1: check for error from ASN1_OP_END__ACT actions
    (bnc#1012382).

  - asn.1: fix out-of-bounds read when parsing indefinite
    length item (bnc#1012382).

  - ath9k: fix tx99 potential info leak (bnc#1012382).

  - atm: horizon: Fix irq release error (bnc#1012382).

  - audit: ensure that 'audit=1' actually enables audit for
    PID 1 (bnc#1012382).

  - axonram: Fix gendisk handling (bnc#1012382).

  - backlight: pwm_bl: Fix overflow condition (bnc#1012382).

  - bcache: add a comment in journal bucket reading
    (bsc#1076110).

  - bcache: Avoid nested function definition (bsc#1076110).

  - bcache: bch_allocator_thread() is not freezable
    (bsc#1076110).

  - bcache: bch_writeback_thread() is not freezable
    (bsc#1076110).

  - bcache: check return value of register_shrinker
    (bsc#1076110).

  - bcache: documentation formatting, edited for clarity,
    stripe alignment notes (bsc#1076110).

  - bcache: documentation updates and corrections
    (bsc#1076110).

  - bcache: Do not reinvent the wheel but use existing llist
    API (bsc#1076110).

  - bcache: do not write back data if reading it failed
    (bsc#1076110).

  - bcache: explicitly destroy mutex while exiting
    (bnc#1012382).

  - bcache: fix a comments typo in bch_alloc_sectors()
    (bsc#1076110).

  - bcache: fix sequential large write IO bypass
    (bsc#1076110).

  - bcache: fix wrong cache_misses statistics (bnc#1012382).

  - bcache: gc does not work when triggering by manual
    command (bsc#1076110, bsc#1038078).

  - bcache: implement PI controller for writeback rate
    (bsc#1076110).

  - bcache: increase the number of open buckets
    (bsc#1076110).

  - bcache: only permit to recovery read error when cache
    device is clean (bnc#1012382 bsc#1043652).

  - bcache: partition support: add 16 minors per bcacheN
    device (bsc#1076110, bsc#1019784).

  - bcache: rearrange writeback main thread ratelimit
    (bsc#1076110).

  - bcache: recover data from backing when data is clean
    (bnc#1012382 bsc#1043652).

  - bcache: Remove redundant set_capacity (bsc#1076110).

  - bcache: remove unused parameter (bsc#1076110).

  - bcache: rewrite multiple partitions support
    (bsc#1076110, bsc#1038085).

  - bcache: safeguard a dangerous addressing in
    closure_queue (bsc#1076110).

  - bcache: silence static checker warning (bsc#1076110).

  - bcache: smooth writeback rate control (bsc#1076110).

  - bcache.txt: standardize document format (bsc#1076110).

  - bcache: update bio->bi_opf bypass/writeback REQ_ flag
    hints (bsc#1076110).

  - bcache: update bucket_in_use in real time (bsc#1076110).

  - bcache: Update continue_at() documentation
    (bsc#1076110).

  - bcache: use kmalloc to allocate bio in bch_data_verify()
    (bsc#1076110).

  - bcache: use llist_for_each_entry_safe() in
    __closure_wake_up() (bsc#1076110).

  - bcache: writeback rate clamping: make 32 bit safe
    (bsc#1076110).

  - bcache: writeback rate shouldn't artifically clamp
    (bsc#1076110).

  - be2net: restore properly promisc mode after queues
    reconfiguration (bsc#963844 FATE#320192).

  - block: wake up all tasks blocked in get_request()
    (bnc#1012382).

  - bluetooth: btusb: driver to enable the usb-wakeup
    feature (bnc#1012382).

  - bnx2x: do not rollback VF MAC/VLAN filters we did not
    configure (bnc#1012382).

  - bnx2x: fix possible overrun of VFPF multicast addresses
    array (bnc#1012382).

  - bnx2x: prevent crash when accessing PTP with interface
    down (bnc#1012382).

  - btrfs: add missing memset while reading compressed
    inline extents (bnc#1012382).

  - can: af_can: canfd_rcv(): replace WARN_ONCE by
    pr_warn_once (bnc#1012382).

  - can: af_can: can_rcv(): replace WARN_ONCE by
    pr_warn_once (bnc#1012382).

  - can: ems_usb: cancel urb on -EPIPE and -EPROTO
    (bnc#1012382).

  - can: esd_usb2: cancel urb on -EPIPE and -EPROTO
    (bnc#1012382).

  - can: gs_usb: fix return value of the 'set_bittiming'
    callback (bnc#1012382).

  - can: kvaser_usb: cancel urb on -EPIPE and -EPROTO
    (bnc#1012382).

  - can: kvaser_usb: Fix comparison bug in
    kvaser_usb_read_bulk_callback() (bnc#1012382).

  - can: kvaser_usb: free buf in error paths (bnc#1012382).

  - can: kvaser_usb: ratelimit errors if incomplete messages
    are received (bnc#1012382).

  - can: peak: fix potential bug in packet fragmentation
    (bnc#1012382).

  - can: ti_hecc: Fix napi poll return value for repoll
    (bnc#1012382).

  - can: usb_8dev: cancel urb on -EPIPE and -EPROTO
    (bnc#1012382).

  - cdc-acm: apply quirk for card reader (bsc#1060279).

  - cdrom: factor out common open_for_* code (bsc#1048585).

  - cdrom: wait for tray to close (bsc#1048585).

  - ceph: more accurate statfs (bsc#1077068).

  - clk: imx6: refine hdmi_isfr's parent to make HDMI work
    on i.MX6 SoCs w/o VPU (bnc#1012382).

  - clk: mediatek: add the option for determining PLL source
    clock (bnc#1012382).

  - clk: tegra: Fix cclk_lp divisor register (bnc#1012382).

  - config: arm64: enable HARDEN_BRANCH_PREDICTOR

  - config: arm64: enable UNMAP_KERNEL_AT_EL0

  - cpuidle: fix broadcast control when broadcast can not be
    entered (bnc#1012382).

  - cpuidle: powernv: Pass correct drv->cpumask for
    registration (bnc#1012382).

  - cpuidle: Validate cpu_dev in cpuidle_add_sysfs()
    (bnc#1012382).

  - crypto: algapi - fix NULL dereference in
    crypto_remove_spawns() (bnc#1012382).

  - crypto: chacha20poly1305 - validate the digest size
    (bnc#1012382).

  - crypto: chelsio - select CRYPTO_GF128MUL (bsc#1048325).

  - crypto: crypto4xx - increase context and scatter ring
    buffer elements (bnc#1012382).

  - crypto: deadlock between
    crypto_alg_sem/rtnl_mutex/genl_mutex (bnc#1012382).

  - crypto: mcryptd - protect the per-CPU queue with a lock
    (bnc#1012382).

  - crypto: n2 - cure use after free (bnc#1012382).

  - crypto: pcrypt - fix freeing pcrypt instances
    (bnc#1012382).

  - crypto: s5p-sss - Fix completing crypto request in IRQ
    handler (bnc#1012382).

  - crypto: tcrypt - fix buffer lengths in test_aead_speed()
    (bnc#1012382).

  - cxl: Check if vphb exists before iterating over AFU
    devices (bsc#1066223).

  - dax: Pass detailed error code from __dax_fault()
    (bsc#1072484).

  - dccp: do not restart ccid2_hc_tx_rto_expire() if sk in
    closed state (bnc#1012382).

  - delay: add poll_event_interruptible (bsc#1048585).

  - dlm: fix malfunction of dlm_tool caused by debugfs
    changes (bsc#1077704).

  - dmaengine: dmatest: move callback wait queue to thread
    context (bnc#1012382).

  - dmaengine: Fix array index out of bounds warning in
    __get_unmap_pool() (bnc#1012382).

  - dmaengine: pl330: fix double lock (bnc#1012382).

  - dmaengine: ti-dma-crossbar: Correct am335x/am43xx mux
    value type (bnc#1012382).

  - dm btree: fix serious bug in btree_split_beneath()
    (bnc#1012382).

  - dm bufio: fix shrinker scans when (nr_to_scan <
    retain_target) (bnc#1012382).

  - dm thin metadata: THIN_MAX_CONCURRENT_LOCKS should be 6
    (bnc#1012382).

  - drivers/firmware: Expose psci_get_version through
    psci_ops structure (bsc#1068032).

  - drm/amd/amdgpu: fix console deadlock if late init failed
    (bnc#1012382).

  - drm: extra printk() wrapper macros (bnc#1012382).

  - drm/exynos/decon5433: set STANDALONE_UPDATE_F on output
    enablement (bnc#1012382).

  - drm/exynos: gem: Drop NONCONTIG flag for buffers
    allocated without IOMMU (bnc#1012382).

  - drm/omap: fix dmabuf mmap for dma_alloc'ed buffers
    (bnc#1012382).

  - drm/radeon: reinstate oland workaround for sclk
    (bnc#1012382).

  - drm/radeon/si: add dpm quirk for Oland (bnc#1012382).

  - drm/vmwgfx: Potential off by one in vmw_view_add()
    (bnc#1012382).

  - dynamic-debug-howto: fix optional/omitted ending line
    number to be LARGE instead of 0 (bnc#1012382).

  - edac, i5000, i5400: Fix definition of NRECMEMB register
    (bnc#1012382).

  - edac, i5000, i5400: Fix use of MTR_DRAM_WIDTH macro
    (bnc#1012382).

  - edac, sb_edac: Fix missing break in switch
    (bnc#1012382).

  - efi/esrt: Cleanup bad memory map log messages
    (bnc#1012382).

  - efi: Move some sysfs files to be read-only by root
    (bnc#1012382).

  - eventpoll.h: add missing epoll event masks
    (bnc#1012382).

  - ext4: fix crash when a directory's i_size is too small
    (bnc#1012382).

  - ext4: Fix ENOSPC handling in DAX page fault handle
    (bsc#1072484).

  - ext4: fix fdatasync(2) after fallocate(2) operation
    (bnc#1012382).

  - fbdev: controlfb: Add missing modes to fix out of bounds
    access (bnc#1012382).

  - Fix build error in vma.c (bnc#1012382).

  - Fixup hang when calling 'nvme list' on all paths down
    (bsc#1070052).

  - fjes: Fix wrong netdevice feature flags (bnc#1012382).

  - flow_dissector: properly cap thoff field (bnc#1012382).

  - fm10k: ensure we process SM mbx when processing VF mbx
    (bnc#1012382).

  - fork: clear thread stack upon allocation (bsc#1077560).

  - fscache: Fix the default for
    fscache_maybe_release_page() (bnc#1012382).

  - futex: Prevent overflow by strengthen input validation
    (bnc#1012382).

  - gcov: disable for COMPILE_TEST (bnc#1012382).

  - gfs2: Take inode off order_write list when setting jdata
    flag (bnc#1012382).

  - gpio: altera: Use handle_level_irq when configured as a
    level_high (bnc#1012382).

  - hid: chicony: Add support for another ASUS Zen AiO
    keyboard (bnc#1012382).

  - hid: xinmo: fix for out of range for THT 2P arcade
    controller (bnc#1012382).

  - hrtimer: Reset hrtimer cpu base proper on CPU hotplug
    (bnc#1012382).

  - hv: kvp: Avoid reading past allocated blocks from KVP
    file (bnc#1012382).

  - hwmon: (asus_atk0110) fix uninitialized data access
    (bnc#1012382).

  - i40iw: Account for IPv6 header when setting MSS
    (bsc#1024376 FATE#321249).

  - i40iw: Allocate a sdbuf per CQP WQE (bsc#1024376
    FATE#321249).

  - i40iw: Cleanup AE processing (bsc#1024376 FATE#321249).

  - i40iw: Clear CQP Head/Tail during initialization
    (bsc#1024376 FATE#321249).

  - i40iw: Correct ARP index mask (bsc#1024376 FATE#321249).

  - i40iw: Correct Q1/XF object count equation (bsc#969476
    FATE#319648 bsc#969477 FATE#319816).

  - i40iw: Do not allow posting WR after QP is flushed
    (bsc#1024376 FATE#321249).

  - i40iw: Do not free sqbuf when event is
    I40IW_TIMER_TYPE_CLOSE (bsc#1024376 FATE#321249).

  - i40iw: Do not generate CQE for RTR on QP flush
    (bsc#1024376 FATE#321249).

  - i40iw: Do not retransmit MPA request after it is ACKed
    (bsc#1024376 FATE#321249).

  - i40iw: Fixes for static checker warnings (bsc#1024376
    FATE#321249).

  - i40iw: Fix sequence number for the first partial FPDU
    (bsc#969476 FATE#319648 bsc#969477 FATE#319816).

  - i40iw: Fix the connection ORD value for loopback
    (bsc#969476 FATE#319648 bsc#969477 FATE#319816).

  - i40iw: Ignore AE source field in AEQE for some AEs
    (bsc#1024376 FATE#321249).

  - i40iw: Move cqp_cmd_head init to CQP initialization
    (bsc#1024376 FATE#321249).

  - i40iw: Move exception_lan_queue to VSI structure
    (bsc#1024376 FATE#321249).

  - i40iw: Move MPA request event for loopback after connect
    (bsc#1024376 FATE#321249).

  - i40iw: Notify user of established connection after QP in
    RTS (bsc#1024376 FATE#321249).

  - i40iw: Reinitialize IEQ on MTU change (bsc#1024376
    FATE#321249).

  - i40iw: Remove limit on re-posting AEQ entries to HW
    (bsc#969476 FATE#319648 bsc#969477 FATE#319816).

  - i40iw: Selectively teardown QPs on IP addr change event
    (bsc#1024376 FATE#321249).

  - i40iw: Validate correct IRD/ORD connection parameters
    (bsc#969476 FATE#319648 bsc#969477 FATE#319816).

  - ib/hfi1: Fix misspelling in comment (bsc#973818,
    fate#319242).

  - ib/hfi1: Prevent kernel QP post send hard lockups
    (bsc#973818 FATE#319242).

  - ib/ipoib: Fix lockdep issue found on
    ipoib_ib_dev_heavy_flush (git-fixes).

  - ib/ipoib: Fix race condition in neigh creation
    (bsc#1022595 FATE#322350).

  - ib/ipoib: Grab rtnl lock on heavy flush when calling
    ndo_open/stop (bnc#1012382).

  - ib/mlx4: Increase maximal message size under UD QP
    (bnc#1012382).

  - ib/mlx5: Assign send CQ and recv CQ of UMR QP
    (bnc#1012382).

  - ib/mlx5: Serialize access to the VMA list (bsc#1015342
    FATE#321688 bsc#1015343 FATE#321689).

  - ibmvnic: Allocate and request vpd in init_resources
    (bsc#1076872).

  - ibmvnic: Do not handle RX interrupts when not up
    (bsc#1075066).

  - ibmvnic: fix firmware version when no firmware level has
    been provided by the VIOS server (bsc#1079038).

  - ibmvnic: Fix IP offload control buffer (bsc#1076899).

  - ibmvnic: Fix IPv6 packet descriptors (bsc#1076899).

  - ibmvnic: Fix pending MAC address changes (bsc#1075627).

  - ibmvnic: Modify buffer size and number of queues on
    failover (bsc#1076872).

  - ibmvnic: Revert to previous mtu when unsupported value
    requested (bsc#1076872).

  - ibmvnic: Wait for device response when changing MAC
    (bsc#1078681).

  - ib/qib: Fix comparison error with qperf compare/swap
    test (FATE#321231 FATE#321473).

  - ib/rdmavt: restore IRQs on error path in rvt_create_ah()
    (bsc#973818, fate#319242).

  - ib/srpt: Disable RDMA access by the initiator
    (bnc#1012382).

  - ib/srpt: Fix ACL lookup during login (bsc#1024296
    FATE#321265).

  - igb: check memory allocation failure (bnc#1012382).

  - ima: fix hash algorithm initialization (bnc#1012382).

  - inet: frag: release spinlock before calling icmp_send()
    (bnc#1012382).

  - input: 88pm860x-ts - fix child-node lookup
    (bnc#1012382).

  - input: elantech - add new icbody type 15 (bnc#1012382).

  - input: i8042 - add TUXEDO BU1406 (N24_25BU) to the nomux
    list (bnc#1012382).

  - input: trackpoint - force 3 buttons if 0 button is
    reported (bnc#1012382).

  - input: twl4030-vibra - fix sibling-node lookup
    (bnc#1012382).

  - input: twl6040-vibra - fix child-node lookup
    (bnc#1012382).

  - input: twl6040-vibra - fix DT node memory management
    (bnc#1012382).

  - intel_th: pci: Add Gemini Lake support (bnc#1012382).

  - iommu/arm-smmu-v3: Do not free page table ops twice
    (bnc#1012382).

  - iommu/vt-d: Fix scatterlist offset handling
    (bnc#1012382).

  - ip6_gre: remove the incorrect mtu limit for ipgre tap
    (bsc#1022912 FATE#321246).

  - ip6_tunnel: disable dst caching if tunnel is dual-stack
    (bnc#1012382).

  - ipmi: Stop timers before cleaning up the module
    (bnc#1012382).

  - ipv4: Fix use-after-free when flushing FIB tables
    (bnc#1012382).

  - ipv4: igmp: guard against silly MTU values
    (bnc#1012382).

  - ipv4: Make neigh lookup keys for loopback/point-to-point
    devices be INADDR_ANY (bnc#1012382).

  - ipv6: Fix getsockopt() for sockets with default
    IPV6_AUTOFLOWLABEL (bnc#1012382).

  - ipv6: fix possible mem leaks in ipv6_make_skb()
    (bnc#1012382).

  - ipv6: fix udpv6 sendmsg crash caused by too small MTU
    (bnc#1012382).

  - ipv6: ip6_make_skb() needs to clear cork.base.dst
    (git-fixes).

  - ipv6: mcast: better catch silly mtu values
    (bnc#1012382).

  - ipv6: reorder icmpv6_init() and ip6_mr_init()
    (bnc#1012382).

  - ipvlan: fix ipv6 outbound device (bnc#1012382).

  - ipvlan: remove excessive packet scrubbing (bsc#1070799).

  - irda: vlsi_ir: fix check for DMA mapping errors
    (bnc#1012382).

  - irqchip/crossbar: Fix incorrect type of register size
    (bnc#1012382).

  - iscsi_iser: Re-enable 'iser_pi_guard' module parameter
    (bsc#1062129).

  - iscsi-target: fix memory leak in
    lio_target_tiqn_addtpg() (bnc#1012382).

  - iscsi-target: Make TASK_REASSIGN use proper
    se_cmd->cmd_kref (bnc#1012382).

  - isdn: kcapi: avoid uninitialized data (bnc#1012382).

  - iser-target: Fix possible use-after-free in connection
    establishment error (FATE#321732).

  - iw_cxgb4: Only validate the MSN for successful
    completions (bnc#1012382).

  - ixgbe: fix use of uninitialized padding (bnc#1012382).

  - jump_label: Invoke jump_label_test() via
    early_initcall() (bnc#1012382).

  - kabi: Keep KVM stable after enable s390 wire up bpb
    feature (bsc#1076805).

  - kABI: protect struct bpf_map (kabi).

  - kABI: protect struct ipv6_pinfo (kabi).

  - kABI: protect struct t10_alua_tg_pt_gp (kabi).

  - kABI: protect struct usbip_device (kabi).

  - kabi/severities: arm64: ignore cpu capability array

  - kabi/severities: do not care about stuff_RSB

  - kaiser: Set _PAGE_NX only if supported (bnc#1012382).

  - kaiser: Set _PAGE_NX only if supported (bnc#1012382).

  - kbuild: add '-fno-stack-check' to kernel build options
    (bnc#1012382).

  - kbuild: modversions for EXPORT_SYMBOL() for asm
    (bsc#1074621 bsc#1068032).

  - kbuild: pkg: use --transform option to prefix paths in
    tar (bnc#1012382).

  - kdb: Fix handling of kallsyms_symbol_next() return value
    (bnc#1012382).

  - kernel/acct.c: fix the acct->needcheck check in
    check_free_space() (bnc#1012382).

  - kernel: make groups_sort calling a responsibility
    group_info allocators (bnc#1012382).

  - kernel/signal.c: protect the SIGNAL_UNKILLABLE tasks
    from !sig_kernel_only() signals (bnc#1012382).

  - kernel/signal.c: protect the traced SIGNAL_UNKILLABLE
    tasks from SIGKILL (bnc#1012382).

  - kernel/signal.c: remove the no longer needed
    SIGNAL_UNKILLABLE check in complete_signal()
    (bnc#1012382).

  - keys: add missing permission check for request_key()
    destination (bnc#1012382).

  - kprobes/x86: Disable preemption in ftrace-based jprobes
    (bnc#1012382).

  - kpti: Rename to PAGE_TABLE_ISOLATION (bnc#1012382).

  - kpti: Report when enabled (bnc#1012382).

  - kvm: Fix stack-out-of-bounds read in write_mmio
    (bnc#1012382).

  - kvm: nVMX: reset nested_run_pending if the vCPU is going
    to be reset (bnc#1012382).

  - kvm: nVMX: VMCLEAR should not cause the vCPU to shut
    down (bnc#1012382).

  - kvm: pci-assign: do not map smm memory slot pages in
    vt-d page tables (bnc#1012382).

  - kvm: s390: Enable all facility bits that are known good
    for passthrough (bsc#1076805).

  - kvm: s390: wire up bpb feature (bsc#1076805).

  - kvm: VMX: Fix enable VPID conditions (bnc#1012382).

  - kvm: VMX: remove I/O port 0x80 bypass on Intel hosts
    (bnc#1012382).

  - kvm: vmx: Scrub hardware GPRs at VM-exit (bnc#1012382
    bsc#1068032).

  - kvm: x86: Add memory barrier on vmcs field lookup
    (bnc#1012382).

  - kvm: x86: correct async page present tracepoint
    (bnc#1012382).

  - kvm: X86: Fix load RFLAGS w/o the fixed bit
    (bnc#1012382).

  - kvm: x86: fix RSM when PCID is non-zero (bnc#1012382).

  - l2tp: cleanup l2tp_tunnel_delete calls (bnc#1012382).

  - lan78xx: Fix failure in USB Full Speed (bnc#1012382).

  - libata: apply MAX_SEC_1024 to all LITEON EP1 series
    devices (bnc#1012382).

  - libata: drop WARN from protocol error in
    ata_sff_qc_issue() (bnc#1012382).

  - lib/genalloc.c: make the avail variable an atomic_long_t
    (bnc#1012382).

  - macvlan: Only deliver one copy of the frame to the
    macvlan interface (bnc#1012382).

  - md: more open-coded offset_in_page() (bsc#1076110).

  - media: dvb: i2c transfers over usb cannot be done from
    stack (bnc#1012382).

  - mfd: cros ec: spi: Do not send first message too soon
    (bnc#1012382).

  - mfd: twl4030-audio: Fix sibling-node lookup
    (bnc#1012382).

  - mfd: twl6040: Fix child-node lookup (bnc#1012382).

  - mlxsw: reg: Fix SPVMLR max record count (bnc#1012382).

  - mlxsw: reg: Fix SPVM max record count (bnc#1012382).

  - mm: avoid returning VM_FAULT_RETRY from ->page_mkwrite
    handlers (bnc#1012382).

  - mmc: mediatek: Fixed bug where clock frequency could be
    set wrong (bnc#1012382).

  - mm: drop unused pmdp_huge_get_and_clear_notify()
    (bnc#1012382).

  - mm: Handle 0 flags in _calc_vm_trans() macro
    (bnc#1012382).

  - mm/mprotect: add a cond_resched() inside
    change_pmd_range() (bnc#1077871, bnc#1078002).

  - mm/vmstat: Make NR_TLB_REMOTE_FLUSH_RECEIVED available
    even on UP (bnc#1012382).

  - module: Add retpoline tag to VERMAGIC (bnc#1012382).

  - module: set __jump_table alignment to 8 (bnc#1012382).

  - more bio_map_user_iov() leak fixes (bnc#1012382).

  - net: Allow neigh contructor functions ability to modify
    the primary_key (bnc#1012382).

  - net/appletalk: Fix kernel memory disclosure
    (bnc#1012382).

  - net: bcmgenet: correct MIB access of UniMAC RUNT
    counters (bnc#1012382).

  - net: bcmgenet: correct the RBUF_OVFL_CNT and
    RBUF_ERR_CNT MIB values (bnc#1012382).

  - net: bcmgenet: power down internal phy if open or resume
    fails (bnc#1012382).

  - net: bcmgenet: Power up the internal PHY before probing
    the MII (bnc#1012382).

  - net: bcmgenet: reserved phy revisions must be checked
    first (bnc#1012382).

  - net: bridge: fix early call to br_stp_change_bridge_id
    and plug newlink leaks (bnc#1012382).

  - net: core: fix module type in sock_diag_bind
    (bnc#1012382).

  - net: Do not allow negative values for busy_read and
    busy_poll sysctl interfaces (bnc#1012382).

  - net: fec: fix multicast filtering hardware setup
    (bnc#1012382).

  - netfilter: bridge: honor frag_max_size when
    refragmenting (bnc#1012382).

  - netfilter: do not track fragmented packets
    (bnc#1012382).

  - netfilter: ipvs: Fix inappropriate output of procfs
    (bnc#1012382).

  - netfilter: nfnetlink_queue: fix secctx memory leak
    (bnc#1012382).

  - netfilter: nfnetlink_queue: fix timestamp attribute
    (bsc#1074134).

  - netfilter: nfnl_cthelper: fix a race when walk the
    nf_ct_helper_hash table (bnc#1012382).

  - netfilter: nfnl_cthelper: Fix memory leak (bnc#1012382).

  - netfilter: nfnl_cthelper: fix runtime expectation policy
    updates (bnc#1012382).

  - net: Fix double free and memory corruption in
    get_net_ns_by_id() (bnc#1012382).

  - net: igmp: fix source address check for IGMPv3 reports
    (bnc#1012382).

  - net: igmp: Use correct source address on IGMPv3 reports
    (bnc#1012382).

  - net: initialize msg.msg_flags in recvfrom (bnc#1012382).

  - net: ipv4: fix for a race condition in raw_sendmsg
    (bnc#1012382).

  - net/mac80211/debugfs.c: prevent build failure with
    CONFIG_UBSAN=y (bnc#1012382).

  - net/mlx5: Avoid NULL pointer dereference on steering
    cleanup (bsc#1015342 FATE#321688 bsc#1015343
    FATE#321689).

  - net/mlx5: Cleanup IRQs in case of unload failure
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5e: Add refcount to VXLAN structure (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5e: Fix features check of IPv6 traffic
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5e: Fix fixpoint divide exception in
    mlx5e_am_stats_compare (bsc#1015342).

  - net/mlx5e: Fix possible deadlock of VXLAN lock
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5e: Prevent possible races in VXLAN control flow
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5: Fix rate limit packet pacing naming and struct
    (bsc#1015342 FATE#321688 bsc#1015343 FATE#321689).

  - net/mlx5: Stay in polling mode when command EQ destroy
    fails (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net: mvmdio: disable/unprepare clocks in EPROBE_DEFER
    case (bnc#1012382).

  - net: mvneta: clear interface link status on port disable
    (bnc#1012382).

  - net: mvneta: eliminate wrong call to handle rx
    descriptor error (fate#319899).

  - net: mvneta: use proper rxq_number in loop on rx queues
    (fate#319899).

  - net/packet: fix a race in packet_bind() and
    packet_notifier() (bnc#1012382).

  - net: phy: at803x: Change error to EINVAL for invalid MAC
    (bnc#1012382).

  - net: phy: micrel: ksz9031: reconfigure autoneg after phy
    autoneg workaround (bnc#1012382).

  - net: qdisc_pkt_len_init() should be more robust
    (bnc#1012382).

  - net: qmi_wwan: add Sierra EM7565 1199:9091
    (bnc#1012382).

  - net: qmi_wwan: Add USB IDs for MDM6600 modem on Motorola
    Droid 4 (bnc#1012382).

  - net: reevalulate autoflowlabel setting after sysctl
    setting (bnc#1012382).

  - net: Resend IGMP memberships upon peer notification
    (bnc#1012382).

  - net: sctp: fix array overrun read on sctp_timer_tbl
    (bnc#1012382).

  - net: stmmac: enable EEE in MII, GMII or RGMII only
    (bnc#1012382).

  - net: systemport: Pad packet before inserting TSB
    (bnc#1012382).

  - net: systemport: Utilize skb_put_padto() (bnc#1012382).

  - net: tcp: close sock if net namespace is exiting
    (bnc#1012382).

  - net: wimax/i2400m: fix NULL-deref at probe
    (bnc#1012382).

  - nfs: Add a cond_resched() to nfs_commit_release_pages()
    (bsc#1077779).

  - nfsd: auth: Fix gid sorting when rootsquash enabled
    (bnc#1012382).

  - nfsd: fix nfsd_minorversion(.., NFSD_AVAIL)
    (bnc#1012382).

  - nfsd: fix nfsd_reset_versions for NFSv4 (bnc#1012382).

  - nfs: Do not take a reference on fl->fl_file for LOCK
    operation (bnc#1012382).

  - nfs: Fix a typo in nfs_rename() (bnc#1012382).

  - nfsv4.1 respect server's max size in CREATE_SESSION
    (bnc#1012382).

  - nfsv4: Fix client recovery when server reboots multiple
    times (bnc#1012382).

  - nohz: Prevent a timer interrupt storm in
    tick_nohz_stop_sched_tick() (bnc#1012382).

  - n_tty: fix EXTPROC vs ICANON interaction with TIOCINQ
    (aka FIONREAD) (bnc#1012382).

  - nvme_fc: correct hang in nvme_ns_remove() (bsc#1075811).

  - nvme_fc: fix rogue admin cmds stalling teardown
    (bsc#1075811).

  - nvme-fc: merge error on sles12sp3 for reset_work
    (bsc#1079195).

  - nvme-pci: Remove watchdog timer (bsc#1066163).

  - openrisc: fix issue handling 8 byte get_user calls
    (bnc#1012382).

  - packet: fix crash in fanout_demux_rollover()
    (bnc#1012382).

  - parisc: Fix alignment of pa_tlb_lock in assembly on
    32-bit SMP kernel (bnc#1012382).

  - parisc: Hide Diva-built-in serial aux and graphics card
    (bnc#1012382).

  - partially revert tipc improve link resiliency when rps
    is activated (bsc#1068038).

  - pci/AER: Report non-fatal errors only to the affected
    endpoint (bnc#1012382).

  - pci: Avoid bus reset if bridge itself is broken
    (bnc#1012382).

  - pci: Create SR-IOV virtfn/physfn links before attaching
    driver (bnc#1012382).

  - pci: Detach driver before procfs & sysfs teardown on
    device remove (bnc#1012382).

  - pci/PME: Handle invalid data when reading Root Status
    (bnc#1012382).

  - pci / PM: Force devices to D0 in pci_pm_thaw_noirq()
    (bnc#1012382).

  - perf symbols: Fix symbols__fixup_end heuristic for
    corner cases (bnc#1012382).

  - perf test attr: Fix ignored test case result
    (bnc#1012382).

  - phy: work around 'phys' references to usb-nop-xceiv
    devices (bnc#1012382).

  - pinctrl: adi2: Fix Kconfig build problem (bnc#1012382).

  - pinctrl: st: add irq_request/release_resources callbacks
    (bnc#1012382).

  - pipe: avoid round_pipe_size() nr_pages overflow on
    32-bit (bnc#1012382).

  - powerpc/64: Add macros for annotating the destination of
    rfid/hrfid (bsc#1068032, bsc#1075087).

  - powerpc/64: Convert fast_exception_return to use
    RFI_TO_USER/KERNEL (bsc#1068032, bsc#1075087).

  - powerpc/64: Convert the syscall exit path to use
    RFI_TO_USER/KERNEL (bsc#1068032, bsc#1075087).

  - powerpc/64s: Add EX_SIZE definition for paca exception
    save areas (bsc#1068032, bsc#1075087).

  - powerpc/64s: Add support for RFI flush of L1-D cache
    (bsc#1068032, bsc#1075087).

  - powerpc/64s: Allow control of RFI flush via debugfs
    (bsc#1068032, bsc#1075087).

  - powerpc/64s: Convert slb_miss_common to use
    RFI_TO_USER/KERNEL (bsc#1068032, bsc#1075087).

  - powerpc/64s: Simple RFI macro conversions (bsc#1068032,
    bsc#1075087).

  - powerpc/64s: Support disabling RFI flush with
    no_rfi_flush and nopti (bsc#1068032, bsc#1075087).

  - powerpc/64s: Wire up cpu_show_meltdown() (bsc#1068032).

  - powerpc/asm: Allow including ppc_asm.h in asm files
    (bsc#1068032, bsc#1075087).

  - powerpc/ipic: Fix status get and status clear
    (bnc#1012382).

  - powerpc/perf: Dereference BHRB entries safely
    (bsc#1066223).

  - powerpc/perf/hv-24x7: Fix incorrect comparison in memord
    (bnc#1012382).

  - powerpc/powernv: Check device-tree for RFI flush
    settings (bsc#1068032, bsc#1075087).

  - powerpc/powernv/cpufreq: Fix the frequency read by
    /proc/cpuinfo (bnc#1012382).

  - powerpc/powernv/ioda2: Gracefully fail if too many TCE
    levels requested (bnc#1012382).

  - powerpc/pseries: include linux/types.h in asm/hvcall.h
    (bsc#1068032, bsc#1075087).

  - powerpc/pseries: Introduce H_GET_CPU_CHARACTERISTICS
    (bsc#1068032, bsc#1075087).

  - powerpc/pseries: Query hypervisor for RFI flush settings
    (bsc#1068032, bsc#1075087).

  - powerpc/pseries/rfi-flush: Call setup_rfi_flush() after
    LPM migration (bsc#1068032, bsc#1075087).

  - powerpc/pseries: rfi-flush: Call setup_rfi_flush() after
    LPM migration (bsc#1068032, bsc#1075087). 

  - powerpc/rfi-flush: Add DEBUG_RFI config option
    (bsc#1068032, bsc#1075087).

  - powerpc/rfi-flush: Make setup_rfi_flush() not __init
    (bsc#1068032, bsc#1075087).

  - powerpc/rfi-flush: Move RFI flush fields out of the paca
    (unbreak kABI) (bsc#1068032, bsc#1075087).

  - powerpc/rfi-flush: Move the logic to avoid a redo into
    the sysfs code (bsc#1068032, bsc#1075087).

  - powerpc/rfi-flush: prevent crash when changing flush
    type to fallback after system boot (bsc#1068032,
    bsc#1075087).

  - ppp: Destroy the mutex when cleanup (bnc#1012382).

  - pppoe: take ->needed_headroom of lower device into
    account on xmit (bnc#1012382).

  - pti: unbreak EFI (bsc#1074709).

  - r8152: fix the list rx_done may be used without
    initialization (bnc#1012382).

  - r8152: prevent the driver from transmitting packets with
    carrier off (bnc#1012382).

  - r8169: fix memory corruption on retrieval of hardware
    statistics (bnc#1012382).

  - raid5: Set R5_Expanded on parity devices as well as data
    (bnc#1012382).

  - ravb: Remove Rx overflow log messages (bnc#1012382).

  - rbd: set max_segments to USHRT_MAX (bnc#1012382).

  - rdma/cma: Avoid triggering undefined behavior
    (bnc#1012382).

  - rdma/i40iw: Remove MSS change support (bsc#1024376
    FATE#321249).

  - rds: Fix NULL pointer dereference in __rds_rdma_map
    (bnc#1012382).

  - rds: Heap OOB write in rds_message_alloc_sgs()
    (bnc#1012382).

  - rds: NULL pointer dereference in rds_atomic_free_op
    (bnc#1012382).

  - regulator: core: Rely on regulator_dev_release to free
    constraints (bsc#1074847).

  - regulator: da9063: Return an error code on probe failure
    (bsc#1074847).

  - regulator: pwm: Fix regulator ramp delay for continuous
    mode (bsc#1074847).

  - regulator: Try to resolve regulators supplies on
    registration (bsc#1074847).

  - Revert 'Bluetooth: btusb: driver to enable the
    usb-wakeup feature' (bnc#1012382).

  - Revert 'drm/armada: Fix compile fail' (bnc#1012382).

  - Revert 'kaiser: vmstat show NR_KAISERTABLE as
    nr_overhead' (kabi).

  - Revert 'lib/genalloc.c: make the avail variable an
    atomic_long_t' (kabi).

  - Revert 'module: Add retpoline tag to VERMAGIC'
    (bnc#1012382 kabi).

  - Revert 'module: Add retpoline tag to VERMAGIC' (kabi).

  - Revert 'ocfs2: should wait dio before inode lock in
    ocfs2_setattr()' (bnc#1012382).

  - Revert 's390/kbuild: enable modversions for symbols
    exported from asm' (bnc#1012382).

  - Revert 'sched/deadline: Use the revised wakeup rule for
    suspending constrained dl tasks' (kabi).

  - Revert 'scsi: libsas: align sata_device's rps_resp on a
    cacheline' (kabi).

  - Revert 'spi: SPI_FSL_DSPI should depend on HAS_DMA'
    (bnc#1012382).

  - Revert 'userfaultfd: selftest: vm: allow to build in vm/
    directory' (bnc#1012382).

  - Revert 'x86/efi: Build our own page table structures'
    (bnc#1012382).

  - Revert 'x86/efi: Hoist page table switching code into
    efi_call_virt()' (bnc#1012382).

  - Revert 'x86/mm/pat: Ensure cpa->pfn only contains page
    frame numbers' (bnc#1012382).

  - rfi-flush: Make DEBUG_RFI a CONFIG option (bsc#1068032,
    bsc#1075087).

  - ring-buffer: Mask out the info bits when returning
    buffer page length (bnc#1012382).

  - route: also update fnhe_genid when updating a route
    cache (bnc#1012382).

  - route: update fnhe_expires for redirect when the fnhe
    exists (bnc#1012382).

  - rtc: cmos: Initialize hpet timer before irq is
    registered (bsc#1077592).

  - rtc: pcf8563: fix output clock rate (bnc#1012382).

  - rtc: pl031: make interrupt optional (bnc#1012382).

  - rtc: set the alarm to the next expiring timer
    (bnc#1012382).

  - s390: always save and restore all registers on context
    switch (bnc#1012382).

  - s390/cpuinfo: show facilities as reported by stfle
    (bnc#1076847, LTC#163740).

  - s390: fix compat system call table (bnc#1012382).

  - s390/pci: do not require AIS facility (bnc#1012382).

  - s390/qeth: no ETH header for outbound AF_IUCV
    (LTC#156276 bnc#1012382 bnc#1053472).

  - s390/runtime instrumentation: simplify task exit
    handling (bnc#1012382).

  - sch_dsmark: fix invalid skb_cow() usage (bnc#1012382).

  - sched/deadline: Make sure the replenishment timer fires
    in the next period (bnc#1012382).

  - sched/deadline: Throttle a constrained deadline task
    activated after the deadline (bnc#1012382).

  - sched/deadline: Use deadline instead of period when
    calculating overflow (bnc#1012382).

  - sched/deadline: Use the revised wakeup rule for
    suspending constrained dl tasks (bnc#1012382).

  - sched/deadline: Zero out positive runtime after
    throttling constrained tasks (git-fixes).

  - scsi: bfa: integer overflow in debugfs (bnc#1012382).

  - scsi: cxgb4i: fix Tx skb leak (bnc#1012382).

  - scsi: handle ABORTED_COMMAND on Fujitsu ETERNUS
    (bsc#1069138).

  - scsi: hpsa: cleanup sas_phy structures in sysfs when
    unloading (bnc#1012382).

  - scsi: hpsa: destroy sas transport properties before
    scsi_host (bnc#1012382).

  - scsi: libsas: align sata_device's rps_resp on a
    cacheline (bnc#1012382).

  - scsi: lpfc: Use after free in lpfc_rq_buf_free()
    (bsc#1037838).

  - scsi: mpt3sas: Fix IO error occurs on pulling out a
    drive from RAID1 volume created on two SATA drive
    (bnc#1012382).

  - scsi: sd: change allow_restart to bool in sysfs
    interface (bnc#1012382).

  - scsi: sd: change manage_start_stop to bool in sysfs
    interface (bnc#1012382).

  - scsi: sg: disable SET_FORCE_LOW_DMA (bnc#1012382).

  - scsi: sr: wait for the medium to become ready
    (bsc#1048585).

  - sctp: do not allow the v4 socket to bind a v4mapped v6
    address (bnc#1012382).

  - sctp: do not free asoc when it is already dead in
    sctp_sendmsg (bnc#1012382).

  - sctp: Replace use of sockets_allocated with specified
    macro (bnc#1012382).

  - sctp: return error if the asoc has been peeled off in
    sctp_wait_for_sndbuf (bnc#1012382).

  - sctp: use the right sk after waking up from wait_buf
    sleep (bnc#1012382).

  - selftest/powerpc: Fix false failures for skipped tests
    (bnc#1012382).

  - selftests/x86: Add test_vsyscall (bnc#1012382).

  - selftests/x86/ldt_get: Add a few additional tests for
    limits (bnc#1012382).

  - serial: 8250_pci: Add Amazon PCI serial device ID
    (bnc#1012382).

  - serial: 8250: Preserve DLD[7:4] for PORT_XR17V35X
    (bnc#1012382).

  - series.conf: move core networking (including netfilter)
    into sorted section

  - series.conf: whitespace cleanup

  - Set supported_modules_check 1 (bsc#1072163).

  - sfc: do not warn on successful change of MAC
    (bnc#1012382).

  - sh_eth: fix SH7757 GEther initialization (bnc#1012382).

  - sh_eth: fix TSU resource handling (bnc#1012382).

  - sit: update frag_off info (bnc#1012382).

  - sock: free skb in skb_complete_tx_timestamp on error
    (bnc#1012382).

  - sparc64/mm: set fields in deferred pages (bnc#1012382).

  - spi_ks8995: fix 'BUG: key accdaa28 not in .data!'
    (bnc#1012382).

  - spi: sh-msiof: Fix DMA transfer size check
    (bnc#1012382).

  - spi: xilinx: Detect stall with Unknown commands
    (bnc#1012382).

  - staging: android: ashmem: fix a race condition in
    ASHMEM_SET_SIZE ioctl (bnc#1012382).

  - sunrpc: Fix rpc_task_begin trace point (bnc#1012382).

  - sunxi-rsb: Include OF based modalias in device uevent
    (bnc#1012382).

  - sysfs/cpu: Add vulnerability folder (bnc#1012382).

  - sysfs/cpu: Fix typos in vulnerability documentation
    (bnc#1012382).

  - sysfs: spectre_v2, handle spec_ctrl (bsc#1075994
    bsc#1075091).

  - sysrq : fix Show Regs call trace on ARM (bnc#1012382).

  - target: Avoid early CMD_T_PRE_EXECUTE failures during
    ABORT_TASK (bnc#1012382).

  - target/file: Do not return error for UNMAP if length is
    zero (bnc#1012382).

  - target: fix ALUA transition timeout handling
    (bnc#1012382).

  - target:fix condition return in
    core_pr_dump_initiator_port() (bnc#1012382).

  - target: fix race during implicit transition work flushes
    (bnc#1012382).

  - target/iscsi: Fix a race condition in
    iscsit_add_reject_from_cmd() (bnc#1012382).

  - target: Use system workqueue for ALUA transitions
    (bnc#1012382).

  - tcp: correct memory barrier usage in tcp_check_space()
    (bnc#1012382).

  - tcp: fix under-evaluated ssthresh in TCP Vegas
    (bnc#1012382).

  - tcp md5sig: Use skb's saddr when replying to an incoming
    segment (bnc#1012382).

  - tcp: __tcp_hdrlen() helper (bnc#1012382).

  - tg3: Fix rx hang on MTU change with 5717/5719
    (bnc#1012382).

  - thermal/drivers/step_wise: Fix temperature regulation
    misbehavior (bnc#1012382).

  - thermal: hisilicon: Handle return value of
    clk_prepare_enable (bnc#1012382).

  - tipc: fix cleanup at module unload (bnc#1012382).

  - tipc: fix memory leak in tipc_accept_from_sock()
    (bnc#1012382).

  - tipc: improve link resiliency when rps is activated
    (bsc#1068038).

  - tracing: Allocate mask_str buffer dynamically
    (bnc#1012382).

  - tracing: Fix converting enum's from the map in
    trace_event_eval_update() (bnc#1012382).

  - tracing: Fix crash when it fails to alloc ring buffer
    (bnc#1012382).

  - tracing: Fix possible double free on failure of
    allocating trace buffer (bnc#1012382).

  - tracing: Remove extra zeroing out of the ring buffer
    page (bnc#1012382).

  - tty fix oops when rmmod 8250 (bnc#1012382).

  - uas: Always apply US_FL_NO_ATA_1X quirk to Seagate
    devices (bnc#1012382).

  - uas: ignore UAS for Norelsys NS1068(X) chips
    (bnc#1012382).

  - udf: Avoid overflow when session starts at large offset
    (bnc#1012382).

  - um: link vmlinux with -no-pie (bnc#1012382).

  - usb: Add device quirk for Logitech HD Pro Webcam C925e
    (bnc#1012382).

  - usb: add RESET_RESUME for ELSA MicroLink 56K
    (bnc#1012382).

  - usb: core: Add type-specific length check of BOS
    descriptors (bnc#1012382).

  - usb: core: prevent malicious bNumInterfaces overflow
    (bnc#1012382).

  - usb: devio: Prevent integer overflow in
    proc_do_submiturb() (bnc#1012382).

  - usb: Fix off by one in type-specific length check of BOS
    SSP capability (git-fixes).

  - usb: fix usbmon BUG trigger (bnc#1012382).

  - usb: gadget: configs: plug memory leak (bnc#1012382).

  - usb: gadget: ffs: Forbid usb_ep_alloc_request from
    sleeping (bnc#1012382).

  - usb: gadgetfs: Fix a potential memory leak in
    'dev_config()' (bnc#1012382).

  - usb: gadget: f_uvc: Sanity check wMaxPacketSize for
    SuperSpeed (bnc#1012382).

  - usb: gadget: udc: remove pointer dereference after free
    (bnc#1012382).

  - usb: hub: Cycle HUB power when initialization fails
    (bnc#1012382).

  - usb: Increase usbfs transfer limit (bnc#1012382).

  - usbip: Fix implicit fallthrough warning (bnc#1012382).

  - usbip: Fix potential format overflow in userspace tools
    (bnc#1012382).

  - usbip: fix stub_rx: get_pipe() to validate endpoint
    number (bnc#1012382).

  - usbip: fix stub_rx: harden CMD_SUBMIT path to handle
    malicious input (bnc#1012382).

  - usbip: fix stub_send_ret_submit() vulnerability to null
    transfer_buffer (bnc#1012382).

  - usbip: fix usbip bind writing random string after
    command in match_busid (bnc#1012382).

  - usbip: prevent leaking socket pointer address in
    messages (bnc#1012382).

  - usbip: prevent vhci_hcd driver from leaking a socket
    pointer address (bnc#1012382).

  - usbip: remove kernel addresses from usb device and urb
    debug msgs (bnc#1012382).

  - usbip: stub: stop printing kernel pointer addresses in
    messages (bnc#1012382).

  - usbip: vhci: stop printing kernel pointer addresses in
    messages (bnc#1012382).

  - usb: misc: usb3503: make sure reset is low for at least
    100us (bnc#1012382).

  - usb: musb: da8xx: fix babble condition handling
    (bnc#1012382).

  - usb: phy: isp1301: Add OF device ID table (bnc#1012382).

  - usb: phy: isp1301: Fix build warning when CONFIG_OF is
    disabled (git-fixes).

  - usb: phy: tahvo: fix error handling in tahvo_usb_probe()
    (bnc#1012382).

  - usb: quirks: Add no-lpm quirk for KY-688 USB 3.1 Type-C
    Hub (bnc#1012382).

  - usb: serial: cp210x: add IDs for LifeScan OneTouch Verio
    IQ (bnc#1012382).

  - usb: serial: cp210x: add new device ID ELV ALC 8xxx
    (bnc#1012382).

  - usb: serial: ftdi_sio: add id for Airbus DS P8GR
    (bnc#1012382).

  - usb: serial: option: adding support for YUGA CLM920-NC5
    (bnc#1012382).

  - usb: serial: option: add Quectel BG96 id (bnc#1012382).

  - usb: serial: option: add support for Telit ME910 PID
    0x1101 (bnc#1012382).

  - usb: serial: qcserial: add Sierra Wireless EM7565
    (bnc#1012382).

  - usb: uas and storage: Add US_FL_BROKEN_FUA for another
    JMicron JMS567 ID (bnc#1012382).

  - usb: usbfs: Filter flags passed in from user space
    (bnc#1012382).

  - usb: usbip: Fix possible deadlocks reported by lockdep
    (bnc#1012382).

  - usb: xhci: Add XHCI_TRUST_TX_LENGTH for Renesas
    uPD720201 (bnc#1012382).

  - usb: xhci: fix panic in
    xhci_free_virt_devices_depth_first (bnc#1012382).

  - userfaultfd: selftest: vm: allow to build in vm/
    directory (bnc#1012382).

  - userfaultfd: shmem: __do_fault requires VM_FAULT_NOPAGE
    (bnc#1012382).

  - video: fbdev: au1200fb: Release some resources if a
    memory allocation fails (bnc#1012382).

  - video: fbdev: au1200fb: Return an error code if a memory
    allocation fails (bnc#1012382).

  - virtio: release virtio index when fail to
    device_register (bnc#1012382).

  - vmxnet3: repair memory leak (bnc#1012382).

  - vsyscall: Fix permissions for emulate mode with
    KAISER/PTI (bnc#1012382).

  - vt6655: Fix a possible sleep-in-atomic bug in
    vt6655_suspend (bnc#1012382).

  - vti6: Do not report path MTU below IPV6_MIN_MTU
    (bnc#1012382).

  - vti6: fix device register to report IFLA_INFO_KIND
    (bnc#1012382).

  - workqueue: trigger WARN if queue_delayed_work() is
    called with NULL @wq (bnc#1012382).

  - writeback: fix memory leak in wb_queue_work()
    (bnc#1012382).

  - x.509: fix buffer overflow detection in sprint_oid()
    (bsc#1075078).

  - x.509: reject invalid BIT STRING for subjectPublicKey
    (bnc#1012382).

  - x86/acpi: Handle SCI interrupts above legacy space
    gracefully (bsc#1068984).

  - x86/acpi: Reduce code duplication in
    mp_override_legacy_irq() (bsc#1068984).

  - x86/alternatives: Add missing '\n' at end of ALTERNATIVE
    inline asm (bnc#1012382).

  - x86/alternatives: Fix optimize_nops() checking
    (bnc#1012382).

  - x86/apic/vector: Fix off by one in error path
    (bnc#1012382).

  - x86/asm/32: Make sync_core() handle missing CPUID on all
    32-bit kernels (bnc#1012382).

  - x86/boot: Fix early command-line parsing when matching
    at end (bsc#1068032).

  - x86/cpu: Factor out application of forced CPU caps
    (bnc#1012382).

  - x86/cpufeatures: Add X86_BUG_CPU_INSECURE (bnc#1012382).

  - x86/cpufeatures: Add X86_BUG_SPECTRE_V[12]
    (bnc#1012382).

  - x86/cpufeatures: Make CPU bugs sticky (bnc#1012382).

  - x86/cpu: Implement CPU vulnerabilites sysfs functions
    (bnc#1012382).

  - x86/cpu: Merge bugs.c and bugs_64.c (bnc#1012382).

  - x86/cpu: Rename Merrifield2 to Moorefield (bsc#985025).

  - x86/cpu: Rename 'WESTMERE2' family to 'NEHALEM_G'
    (bsc#985025).

  - x86/cpu, x86/pti: Do not enable PTI on AMD processors
    (bnc#1012382).

  - x86/Documentation: Add PTI description (bnc#1012382).

  - x86/efi: Build our own page table structures
    (fate#320512).

  - x86/efi: Hoist page table switching code into
    efi_call_virt() (fate#320512).

  - x86/entry: Use SYSCALL_DEFINE() macros for
    sys_modify_ldt() (bnc#1012382).

  - x86/hpet: Prevent might sleep splat on resume
    (bnc#1012382).

  - x86/kasan: Clear kasan_zero_page after TLB flush
    (bnc#1012382).

  - x86/kasan: Write protect kasan zero shadow
    (bnc#1012382).

  - x86/microcode/intel: Extend BDW late-loading further
    with LLC size check (bnc#1012382).

  - x86/microcode/intel: Extend BDW late-loading with a
    revision check (bnc#1012382).

  - x86/microcode/intel: Fix BDW late-loading revision check
    (bnc#1012382).

  - x86/mm/32: Move setup_clear_cpu_cap(X86_FEATURE_PCID)
    earlier (git-fixes).

  - x86/mm: Disable PCID on 32-bit kernels (bnc#1012382).

  - x86/mm/pat: Ensure cpa->pfn only contains page frame
    numbers (fate#320588).

  - x86/PCI: Make broadcom_postcore_init() check
    acpi_disabled (bnc#1012382).

  - x86/pti: Document fix wrong index (bnc#1012382).

  - x86/pti/efi: broken conversion from efi to kernel page
    table (bnc#1012382).

  - x86/pti: Rename BUG_CPU_INSECURE to BUG_CPU_MELTDOWN
    (bnc#1012382).

  - x86/retpolines/spec_ctrl: disable IBRS on !SKL if
    retpolines are active (bsc#1068032).

  - x86/smpboot: Remove stale TLB flush invocations
    (bnc#1012382).

  - x86/spectre_v2: fix ordering in IBRS initialization
    (bsc#1075994 bsc#1075091).

  - x86/spectre_v2: nospectre_v2 means nospec too
    (bsc#1075994 bsc#1075091).

  - x86/tlb: Drop the _GPL from the cpu_tlbstate export
    (bnc#1012382).

  - x86/vm86/32: Switch to flush_tlb_mm_range() in
    mark_screen_rdonly() (bnc#1012382).

  - xen-netfront: avoid crashing on resume after a failure
    in talk_to_netback() (bnc#1012382).

  - xen-netfront: Improve error handling during
    initialization (bnc#1012382).

  - xfrm: Copy policy family in clone_policy (bnc#1012382).

  - xfs: add configurable error support to metadata buffers
    (bsc#1068569).

  - xfs: add configuration handlers for specific errors
    (bsc#1068569).

  - xfs: add configuration of error failure speed
    (bsc#1068569).

  - xfs: add 'fail at unmount' error handling configuration
    (bsc#1068569).

  - xfs: Add infrastructure needed for error propagation
    during buffer IO failure (bsc#1068569).

  - xfs: address kabi for xfs buffer retry infrastructure
    (kabi).

  - xfs: configurable error behavior via sysfs
    (bsc#1068569).

  - xfs: fix incorrect extent state in
    xfs_bmap_add_extent_unwritten_real (bnc#1012382).

  - xfs: fix log block underflow during recovery cycle
    verification (bnc#1012382).

  - xfs: fix up inode32/64 (re)mount handling (bsc#1069160).

  - xfs: introduce metadata IO error class (bsc#1068569).

  - xfs: introduce table-based init for error behaviors
    (bsc#1068569).

  - xfs: Properly retry failed inode items in case of error
    during buffer writeback (bsc#1068569).

  - xfs: reinit btree pointer on attr tree inactivation walk
    (bsc#1078787).

  - xfs: remove xfs_trans_ail_delete_bulk (bsc#1068569).

  - xfs: validate sb_logsunit is a multiple of the fs
    blocksize (bsc#1077513).

  - xhci: Do not add a virt_dev to the devs array before
    it's fully allocated (bnc#1012382).

  - xhci: Fix ring leak in failure path of
    xhci_alloc_virt_device() (bnc#1012382).

  - xhci: plat: Register shutdown for xhci_plat
    (bnc#1012382).

  - zram: set physical queue limits to avoid array out of
    bounds accesses (bnc#1012382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985025"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-debug-debuginfo-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-default-debuginfo-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-4.4.114-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kselftests-kmp-vanilla-debuginfo-4.4.114-42.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-devel / kernel-macros / kernel-source / etc");
}
