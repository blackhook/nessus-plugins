#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1427.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119077);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10940", "CVE-2018-16658", "CVE-2018-18281", "CVE-2018-18386", "CVE-2018-18690", "CVE-2018-18710", "CVE-2018-9516");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2018-1427)");
  script_summary(english:"Check for the openSUSE-2018-1427 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.162 to receive
various security and bugfixes.

The following security bugs were fixed :

  - CVE-2018-18281: The mremap() syscall performs TLB
    flushes after dropping pagetable locks. If a syscall
    such as ftruncate() removes entries from the pagetables
    of a task that is in the middle of mremap(), a stale TLB
    entry can remain for a short time that permits access to
    a physical page after it has been released back to the
    page allocator and reused. (bnc#1113769).

  - CVE-2018-18710: An information leak in
    cdrom_ioctl_select_disc in drivers/cdrom/cdrom.c could
    be used by local attackers to read kernel memory because
    a cast from unsigned long to int interferes with bounds
    checking. This is similar to CVE-2018-10940 and
    CVE-2018-16658 (bnc#1113751).

  - CVE-2018-18690: A local attacker able to set attributes
    on an xfs filesystem could make this filesystem
    non-operational until the next mount by triggering an
    unchecked error condition during an xfs attribute
    change, because xfs_attr_shortform_addname in
    fs/xfs/libxfs/xfs_attr.c mishandled ATTR_REPLACE
    operations with conversion of an attr from short to long
    form (bnc#1105025).

  - CVE-2018-18386: drivers/tty/n_tty.c allowed local
    attackers (who are able to access pseudo terminals) to
    hang/block further usage of any pseudo terminal devices
    due to an EXTPROC versus ICANON confusion in TIOCINQ
    (bnc#1094825).

  - CVE-2018-9516: A lack of certain checks in the
    hid_debug_events_read() function in the
    drivers/hid/hid-debug.c file might have resulted in
    receiving userspace buffer overflow and an out-of-bounds
    write or to the infinite loop. (bnc#1108498).

The following non-security bugs were fixed :

  - 6lowpan: iphc: reset mac_header after decompress to fix
    panic (bnc#1012382).

  - Add azure kernel description.

  - Add bug reference to
    patches.suse/x86-entry-64-use-a-per-cpu-trampoline-stack
    -fix1.patch

  - Add graphviz to buildreq for image conversion

  - Add reference to bsc#1104124 to
    patches.fixes/fs-aio-fix-the-increment-of-aio-nr-and-cou
    nting-agai.patch

  - ALSA: hda: Add AZX_DCAPS_PM_RUNTIME for AMD Raven Ridge
    (bnc#1012382).

  - ALSA: hda/realtek - Cannot adjust speaker's volume on
    Dell XPS 27 7760 (bnc#1012382).

  - apparmor: remove no-op permission check in policy_unpack
    (git-fixes).

  - ARC: build: Get rid of toolchain check (bnc#1012382).

  - ARC: clone syscall to setp r25 as thread pointer
    (bnc#1012382).

  - arch/hexagon: fix kernel/dma.c build warning
    (bnc#1012382).

  - arch-symbols: use bash as interpreter since the script
    uses bashism.

  - arm64: cpufeature: Track 32bit EL0 support
    (bnc#1012382).

  - arm64: jump_label.h: use asm_volatile_goto macro instead
    of 'asm goto' (bnc#1012382).

  - arm64: KVM: Sanitize PSTATE.M when being set from
    userspace (bnc#1012382).

  - arm64: KVM: Tighten guest core register access from
    userspace (bnc#1012382).

  - ARM: dts: at91: add new compatibility string for macb on
    sama5d3 (bnc#1012382).

  - ARM: dts: dra7: fix DCAN node addresses (bnc#1012382).

  - ARM: mvebu: declare asm symbols as character arrays in
    pmsu.c (bnc#1012382).

  - ASoC: dapm: Fix potential DAI widget pointer deref when
    linking DAIs (bnc#1012382).

  - ASoC: sigmadsp: safeload should not have lower byte
    limit (bnc#1012382).

  - ASoC: wm8804: Add ACPI support (bnc#1012382).

  - ath10k: fix scan crash due to incorrect length
    calculation (bnc#1012382).

  - ath10k: fix use-after-free in ath10k_wmi_cmd_send_nowait
    (bnc#1012382).

  - ath10k: protect ath10k_htt_rx_ring_free with
    rx_ring.lock (bnc#1012382).

  - Bluetooth: Add a new Realtek 8723DE ID 0bda:b009
    (bnc#1012382).

  - bnxt_en: Fix TX timeout during netpoll (bnc#1012382).

  - bonding: avoid possible dead-lock (bnc#1012382).

  - bpf: fix cb access in socket filter programs on tail
    calls (bsc#1012382).

  - bpf: fix map not being uncharged during map creation
    failure (bsc#1012382).

  - bpf, s390: fix potential memleak when later bpf_jit_prog
    fails (git-fixes).

  - bpf, s390x: do not reload skb pointers in non-skb
    context (git-fixes).

  - bsc#1106913: Replace with upstream variants Delete
    patches.suse/11-x86-mm-only-set-ibpb-when-the-new-thread
    -cannot-ptrace-current-thread.patch.

  - bs-upload-kernel: do not set %opensuse_bs Since SLE15 it
    is not set in the distribution project so do not set it
    for kernel projects either.

  - btrfs: add a comp_refs() helper (dependency for
    bsc#1031392).

  - btrfs: add missing initialization in btrfs_check_shared
    (Git-fixes bsc#1112262).

  - btrfs: add tracepoints for outstanding extents mods
    (dependency for bsc#1031392).

  - btrfs: add wrapper for counting BTRFS_MAX_EXTENT_SIZE
    (dependency for bsc#1031392).

  - btrfs: cleanup extent locking sequence (dependency for
    bsc#1031392).

  - btrfs: defrag: use btrfs_mod_outstanding_extents in
    cluster_pages_for_defrag (Follow up fixes for
    bsc#1031392).

  - btrfs: delayed-inode: Remove wrong qgroup meta
    reservation calls (bsc#1031392).

  - btrfs: delayed-inode: Use new qgroup meta rsv for
    delayed inode and item (bsc#1031392).

  - btrfs: Enhance btrfs_trim_fs function to handle error
    better (Dependency for bsc#1113667).

  - btrfs: Ensure btrfs_trim_fs can trim the whole
    filesystem (bsc#1113667).

  - btrfs: fix error handling in btrfs_dev_replace_start
    (bsc#1107535).

  - Btrfs: fix invalid attempt to free reserved space on
    failure to cow range (dependency for bsc#1031392).

  - btrfs: fix missing error return in btrfs_drop_snapshot
    (Git-fixes bsc#1109919).

  - btrfs: Fix race condition between delayed refs and
    blockgroup removal (Git-fixes bsc#1112263).

  - btrfs: Fix wrong btrfs_delalloc_release_extents
    parameter (bsc#1031392).

  - Btrfs: kill trans in run_delalloc_nocow and
    btrfs_cross_ref_exist (dependency for bsc#1031392).

  - btrfs: make the delalloc block rsv per inode (dependency
    for bsc#1031392).

  - Btrfs: pass delayed_refs directly to
    btrfs_find_delayed_ref_head (dependency for
    bsc#1031392).

  - btrfs: qgroup: Add quick exit for non-fs extents
    (dependency for bsc#1031392).

  - btrfs: qgroup: Cleanup
    btrfs_qgroup_prepare_account_extents function
    (dependency for bsc#1031392).

  - btrfs: qgroup: Cleanup the remaining old reservation
    counters (bsc#1031392).

  - btrfs: qgroup: Commit transaction in advance to reduce
    early EDQUOT (bsc#1031392).

  - btrfs: qgroup: Do not use root->qgroup_meta_rsv for
    qgroup (bsc#1031392).

  - btrfs: qgroup: Fix wrong qgroup reservation update for
    relationship modification (bsc#1031392).

  - btrfs: qgroup: Introduce function to convert
    META_PREALLOC into META_PERTRANS (bsc#1031392).

  - btrfs: qgroup: Introduce helpers to update and access
    new qgroup rsv (bsc#1031392).

  - btrfs: qgroup: Make qgroup_reserve and its callers to
    use separate reservation type (bsc#1031392).

  - btrfs: qgroup: Skeleton to support separate qgroup
    reservation type (bsc#1031392).

  - btrfs: qgroups: opencode qgroup_free helper (dependency
    for bsc#1031392).

  - btrfs: qgroup: Split meta rsv type into meta_prealloc
    and meta_pertrans (bsc#1031392).

  - btrfs: qgroup: Update trace events for metadata
    reservation (bsc#1031392).

  - btrfs: qgroup: Update trace events to use new separate
    rsv types (bsc#1031392).

  - btrfs: qgroup: Use independent and accurate per inode
    qgroup rsv (bsc#1031392).

  - btrfs: qgroup: Use root::qgroup_meta_rsv_* to record
    qgroup meta reserved space (bsc#1031392).

  - btrfs: qgroup: Use separate meta reservation type for
    delalloc (bsc#1031392).

  - btrfs: remove type argument from comp_tree_refs
    (dependency for bsc#1031392).

  - Btrfs: rework outstanding_extents (dependency for
    bsc#1031392).

  - btrfs: switch args for comp_*_refs (dependency for
    bsc#1031392).

  - btrfs: Take trans lock before access running trans in
    check_delayed_ref (Follow up fixes for bsc#1031392).

  - ceph: avoid a use-after-free in ceph_destroy_options()
    (bsc#1112007).

  - cfg80211: fix a type issue in
    ieee80211_chandef_to_operating_class() (bnc#1012382).

  - cfg80211: nl80211_update_ft_ies() to validate
    NL80211_ATTR_IE (bnc#1012382).

  - cgroup: Fix deadlock in cpu hotplug path (bnc#1012382).

  - cgroup, netclassid: add a preemption point to
    write_classid (bnc#1098996).

  - CIFS: check for STATUS_USER_SESSION_DELETED
    (bsc#1112902).

  - cifs: connect to servername instead of IP for IPC$ share
    (bsc#1106359).

  - cifs: fix memory leak in SMB2_open() (bsc#1112894).

  - cifs: Fix use after free of a mid_q_entry (bsc#1112903).

  - cifs: read overflow in is_valid_oplock_break()
    (bnc#1012382).

  - clocksource/drivers/ti-32k: Add
    CLOCK_SOURCE_SUSPEND_NONSTOP flag for non-am43 SoCs
    (bnc#1012382).

  - config.sh: set BUGZILLA_PRODUCT for SLE12-SP3

  - crypto: mxs-dcp - Fix wait logic on chan threads
    (bnc#1012382).

  - crypto: skcipher - Fix -Wstringop-truncation warnings
    (bnc#1012382).

  - Define dependencies of in-kernel KMPs statically This
    allows us to use rpm's internal dependency generator
    (bsc#981083).

  - dm cache: fix resize crash if user does not reload cache
    table (bnc#1012382).

  - dm thin metadata: fix __udivdi3 undefined on 32-bit
    (bnc#1012382).

  - dm thin metadata: try to avoid ever aborting
    transactions (bnc#1012382).

  - Do not ship firmware (bsc#1054239). Pull firmware from
    kernel-firmware instead.

  - drivers/tty: add error handling for pcmcia_loop_config
    (bnc#1012382).

  - drm/amdgpu: Fix SDMA HQD destroy error on gfx_v7
    (bnc#1012382).

  - drm/nouveau/TBDdevinit: do not fail when PMU/PRE_OS is
    missing from VBIOS (bnc#1012382).

  - drm/virtio: fix bounds check in
    virtio_gpu_cmd_get_capset() (bsc#1106929)

  - Drop dtb-source.spec and move the sources to
    kernel-source (bsc#1011920)

  - Drop multiversion(kernel) from the KMP template ()

  - e1000: check on netif_running() before calling
    e1000_up() (bnc#1012382).

  - e1000: ensure to free old tx/rx rings in set_ringparam()
    (bnc#1012382).

  - ebtables: arpreply: Add the standard target sanity check
    (bnc#1012382).

  - EDAC, thunderx: Fix memory leak in
    thunderx_l2c_threaded_isr() (bsc#1114648).

  - Enable kernel-obs-(build,qa) also in the vanilla
    branches

  - ethtool: restore erroneously removed break in
    dev_ethtool (bsc#1114229).

  - fbdev: fix broken menu dependencies (bsc#1106929)

  - fbdev/omapfb: fix omapfb_memory_read infoleak
    (bnc#1012382).

  - Fix file list to remove REPORTING-BUGS

  - Fix html and pdf creation in Documetation/media/*

  - floppy: Do not copy a kernel pointer to user memory in
    FDGETPRM ioctl (bnc#1012382).

  - fs/cifs: do not translate SFM_SLASH (U+F026) to
    backslash (bnc#1012382).

  - fs/cifs: suppress a string overflow warning
    (bnc#1012382).

  - gpio: adp5588: Fix sleep-in-atomic-context bug
    (bnc#1012382).

  - hexagon: modify ffs() and fls() to return int
    (bnc#1012382).

  - HID: hid-ntrig: add error handling for
    sysfs_create_group (bnc#1012382).

  - housekeeping: btrfs selftests: fold backport fix into
    backport patch

  - housekeeping: move btrfs patches to sorted section. No
    code changes.

  - hv: avoid crash in vmbus sysfs files (bnc#1108377).

  - hwmon: (adt7475) Make adt7475_read_word() return errors
    (bnc#1012382).

  - hwmon: (ina2xx) fix sysfs shunt resistor read access
    (bnc#1012382).

  - hwrng: core - document the quality field (git-fixes).

  - i2c: i2c-scmi: fix for i2c_smbus_write_block_data
    (bnc#1012382).

  - i2c: i801: Allow ACPI AML access I/O ports not reserved
    for SMBus (bnc#1012382).

  - i2c: uniphier-f: issue STOP only for last message or
    I2C_M_STOP (bnc#1012382).

  - i2c: uniphier: issue STOP only for last message or
    I2C_M_STOP (bnc#1012382).

  - IB/srp: Avoid that sg_reset -d $(srp_device) triggers an
    infinite loop (bnc#1012382).

  - Input: atakbd - fix Atari CapsLock behaviour
    (bnc#1012382).

  - Input: atakbd - fix Atari keymap (bnc#1012382).

  - Input: elantech - enable middle button of touchpad on
    ThinkPad P72 (bnc#1012382).

  - ip6_tunnel: be careful when accessing the inner header
    (bnc#1012382).

  - ip_tunnel: be careful when accessing the inner header
    (bnc#1012382).

  - ipv4: fix use-after-free in ip_cmsg_recv_dstaddr()
    (bnc#1012382).

  - ixgbe: pci_set_drvdata must be called before
    register_netdev (Git-fixes bsc#1109923).

  - jffs2: return -ERANGE when xattr buffer is too small
    (bnc#1012382).

  - KVM: PPC: Book3S HV: Do not truncate HPTE index in xlate
    function (bnc#1012382).

  - KVM: x86: remove eager_fpu field of struct kvm_vcpu_arch
    (bnc#1012382).

  - lib/test_hexdump.c: fix failure on big endian cpu
    (bsc#1106110).

  - mac80211: correct use of IEEE80211_VHT_CAP_RXSTBC_X
    (bnc#1012382).

  - mac80211: fix a race between restart and CSA flows
    (bnc#1012382).

  - mac80211: fix setting IEEE80211_KEY_FLAG_RX_MGMT for AP
    mode keys (bnc#1012382).

  - mac80211: Fix station bandwidth setting after channel
    switch (bnc#1012382).

  - mac80211_hwsim: correct use of
    IEEE80211_VHT_CAP_RXSTBC_X (bnc#1012382).

  - mac80211: mesh: fix HWMP sequence numbering to follow
    standard (bnc#1012382).

  - mac80211: shorten the IBSS debug messages (bnc#1012382).

  - mach64: detect the dot clock divider correctly on sparc
    (bnc#1012382).

  - md-cluster: clear another node's suspend_area after the
    copy is finished (bnc#1012382).

  - media: af9035: prevent buffer overflow on write
    (bnc#1012382).

  - media: exynos4-is: Prevent NULL pointer dereference in
    __isp_video_try_fmt() (bnc#1012382).

  - media: fsl-viu: fix error handling in viu_of_probe()
    (bnc#1012382).

  - media: omap3isp: zero-initialize the isp cam_xclk(a,b)
    initial data (bnc#1012382).

  - media: omap_vout: Fix a possible NULL pointer
    dereference in omap_vout_open() (bsc#1050431).

  - media: s3c-camif: ignore -ENOIOCTLCMD from
    v4l2_subdev_call for s_power (bnc#1012382).

  - media: soc_camera: ov772x: correct setting of banding
    filter (bnc#1012382).

  - media: tm6000: add error handling for
    dvb_register_adapter (bnc#1012382).

  - media: uvcvideo: Support realtek's UVC 1.5 device
    (bnc#1012382).

  - media: v4l: event: Prevent freeing event subscriptions
    while accessed (bnc#1012382).

  - media: videobuf-dma-sg: Fix dma_(sync,unmap)_sg() calls
    (bsc#1050431).

  - memory_hotplug: cond_resched in __remove_pages
    (bnc#1114178).

  - mfd: omap-usb-host: Fix dts probe of children
    (bnc#1012382).

  - mm: madvise(MADV_DODUMP): allow hugetlbfs pages
    (bnc#1012382).

  - mm: /proc/pid/pagemap: hide swap entries from
    unprivileged users (Git-fixes bsc#1109907).

  - mm/vmstat.c: fix outdated vmstat_text (bnc#1012382).

  - mm/vmstat.c: skip NR_TLB_REMOTE_FLUSH* properly
    (bnc#1012382).

  - mm/vmstat.c: skip NR_TLB_REMOTE_FLUSH* properly (git
    fixes).

  - module: exclude SHN_UNDEF symbols from kallsyms api
    (bnc#1012382).

  - move changes without Git-commit out of sorted section

  - net: cadence: Fix a sleep-in-atomic-context bug in
    macb_halt_tx() (bnc#1012382).

  - net: hns: fix length and page_offset overflow when
    CONFIG_ARM64_64K_PAGES (bnc#1012382).

  - net: ipv4: update fnhe_pmtu when first hop's MTU changes
    (bnc#1012382).

  - net/ipv6: Display all addresses in output of
    /proc/net/if_inet6 (bnc#1012382).

  - netlabel: check for IPV4MASK in addrinfo_get
    (bnc#1012382).

  - net: macb: disable scatter-gather for macb on sama5d3
    (bnc#1012382).

  - net/mlx4: Use cpumask_available for eq->affinity_mask
    (bnc#1012382).

  - net: mvpp2: Extract the correct ethtype from the skb for
    tx csum offload (bnc#1012382).

  - net: systemport: Fix wake-up interrupt race during
    resume (bnc#1012382).

  - net/usb: cancel pending work when unbinding smsc75xx
    (bnc#1012382).

  - NFS: add nostatflush mount option (bsc#1065726).

  - NFS: Avoid quadratic search when freeing delegations
    (bsc#1084760).

  - nfsd: fix corrupted reply to badly ordered compound
    (bnc#1012382).

  - ocfs2: fix locking for res->tracking and
    dlm->tracking_list (bnc#1012382).

  - of: unittest: Disable interrupt node tests for old world
    MAC systems (bnc#1012382).

  - ovl: Copy inode attributes after setting xattr
    (bsc#1107299).

  - Pass x86 as architecture on x86_64 and i386
    (bsc#1093118).

  - PCI: hv: Use effective affinity mask (bsc#1109772).

  - PCI: Reprogram bridge prefetch registers on resume
    (bnc#1012382).

  - perf probe powerpc: Ignore SyS symbols irrespective of
    endianness (bnc#1012382).

  - perf script python: Fix export-to-postgresql.py
    occasional failure (bnc#1012382).

  - PM / core: Clear the direct_complete flag on errors
    (bnc#1012382).

  - powerpc/kdump: Handle crashkernel memory reservation
    failure (bnc#1012382).

  - powerpc/numa: Skip onlining a offline node in kdump path
    (bsc#1109784).

  - powerpc/perf/hv-24x7: Fix passing of catalog version
    number (bsc#1053043).

  - powerpc/pseries: Fix build break for SPLPAR=n and CPU
    hotplug (bsc#1079524, git-fixes).

  - powerpc/pseries: Fix CONFIG_NUMA=n build (bsc#1067906,
    git-fixes).

  - powerpc/pseries/mm: call H_BLOCK_REMOVE (bsc#1109158).

  - powerpc/pseries/mm: factorize PTE slot computation
    (bsc#1109158).

  - powerpc/pseries/mm: Introducing FW_FEATURE_BLOCK_REMOVE
    (bsc#1109158).

  - powerpc/rtas: Fix a potential race between CPU-Offline &
    Migration (bsc#1111870).

  - power: vexpress: fix corruption in notifier registration
    (bnc#1012382).

  - proc: restrict kernel stack dumps to root (bnc#1012382).

  - qlcnic: fix Tx descriptor corruption on 82xx devices
    (bnc#1012382).

  - r8169: Clear RTL_FLAG_TASK_*_PENDING when clearing
    RTL_FLAG_TASK_ENABLED (bnc#1012382).

  - RAID10 BUG_ON in raise_barrier when force is true and
    conf->barrier is 0 (bnc#1012382).

  - rculist: add list_for_each_entry_from_rcu()
    (bsc#1084760).

  - rculist: Improve documentation for
    list_for_each_entry_from_rcu() (bsc#1084760).

  - RDMA/ucma: check fd type in ucma_migrate_id()
    (bnc#1012382).

  - README: Clean-up trailing whitespace

  - reiserfs: add check to detect corrupted directory entry
    (bsc#1109818).

  - reiserfs: do not panic on bad directory entries
    (bsc#1109818).

  - resource: Include resource end in walk_*() interfaces
    (bsc#1114648).

  - Revert 'btrfs: qgroups: Retry after commit on getting
    EDQUOT' (bsc#1031392).

  - Revert 'drm: Do not pass negative delta to
    ktime_sub_ns()' (bsc#1106929)

  - Revert 'drm/i915: Initialize HWS page address after GPU
    reset' (bsc#1106929)

  - Revert 'KVM: x86: remove eager_fpu field of struct
    kvm_vcpu_arch' (kabi).

  - Revert 'media: v4l: event: Prevent freeing event
    subscriptions while accessed' (kabi).

  - Revert 'proc: restrict kernel stack dumps to root'
    (kabi).

  - Revert 'rpm/constraints.in: Lower default disk space
    requirement from 25G to 24G' This reverts commit
    406abda1467c038842febffe264faae1fa2e3c1d. ok, did not
    wait long enough to see the failure.

  - Revert 'Skip intel_crt_init for Dell XPS 8700'
    (bsc#1106929)

  - Revert 'tcp: add tcp_ooo_try_coalesce() helper' (kabi).

  - Revert 'tcp: call tcp_drop() from tcp_data_queue_ofo()'
    (kabi).

  - Revert 'tcp: fix a stale ooo_last_skb after a replace'
    (kabi).

  - Revert 'tcp: free batches of packets in
    tcp_prune_ofo_queue()' (kabi).

  - Revert 'tcp: use an RB tree for ooo receive queue'
    (kabi).

  - Revert 'usb: cdc-wdm: Fix a sleep-in-atomic-context bug
    in service_outstanding_interrupt()' (bnc#1012382).

  - Revert 'x86/fpu: Finish excising 'eagerfpu'' (kabi).

  - Revert 'x86/fpu: Remove struct fpu::counter' (kabi).

  - Revert 'x86/fpu: Remove use_eager_fpu()' (kabi).

  - rndis_wlan: potential buffer overflow in
    rndis_wlan_auth_indication() (bnc#1012382).

  - rpm/apply-patches: Fix failure if there are no vanilla
    patches The grep command returns 1 if there are no
    patches and we are using pipefail.

  - rpm/constraints.in: build ARM on at least 2 cpus

  - rpm/constraints.in: Lower default disk space requirement
    from 25G to 24G 25G is rejected by the build service on
    ARM.

  - rtnl: limit IFLA_NUM_TX_QUEUES and IFLA_NUM_RX_QUEUES to
    4096 (bnc#1012382).

  - s390/chsc: Add exception handler for CHSC instruction
    (git-fixes).

  - s390/extmem: fix gcc 8 stringop-overflow warning
    (bnc#1012382).

  - s390/kdump: Fix elfcorehdr size calculation (git-fixes).

  - s390/kdump: Make elfcorehdr size calculation ABI
    compliant (git-fixes).

  - s390/mm: correct allocate_pgste proc_handler callback
    (git-fixes).

  - s390/qeth: do not dump past end of unknown HW header
    (bnc#1012382).

  - s390/qeth: handle failure on workqueue creation
    (git-fixes).

  - s390: revert ELF_ET_DYN_BASE base changes (git-fixes).

  - s390/stacktrace: fix address ranges for asynchronous and
    panic stack (git-fixes).

  - scsi: bnx2i: add error handling for ioremap_nocache
    (bnc#1012382).

  - scsi: ibmvscsi: Improve strings handling (bnc#1012382).

  - scsi: klist: Make it safe to use klists in atomic
    context (bnc#1012382).

  - scsi: target/iscsi: Make iscsit_ta_authentication()
    respect the output buffer size (bnc#1012382).

  - selftests/efivarfs: add required kernel configs
    (bnc#1012382).

  - serial: cpm_uart: return immediately from console poll
    (bnc#1012382).

  - serial: imx: restore handshaking irq for imx1
    (bnc#1012382).

  - signal: Properly deliver SIGSEGV from x86 uprobes
    (bsc#1110006).

  - slub: make ->cpu_partial unsigned int (bnc#1012382).

  - smb2: fix missing files in root share directory listing
    (bnc#1012382).

  - smb3: fill in statfs fsid and correct namelen
    (bsc#1112905).

  - sound: enable interrupt after dma buffer initialization
    (bnc#1012382).

  - spi: rspi: Fix interrupted DMA transfers (bnc#1012382).

  - spi: rspi: Fix invalid SPI use during system suspend
    (bnc#1012382).

  - spi: sh-msiof: Fix handling of write value for SISTR
    register (bnc#1012382).

  - spi: sh-msiof: Fix invalid SPI use during system suspend
    (bnc#1012382).

  - spi: tegra20-slink: explicitly enable/disable clock
    (bnc#1012382).

  - staging: android: ashmem: Fix mmap size validation
    (bnc#1012382).

  - staging: rts5208: fix missing error check on call to
    rtsx_write_register (bnc#1012382).

  - stmmac: fix valid numbers of unicast filter entries
    (bnc#1012382).

  - target: log Data-Out timeouts as errors (bsc#1095805).

  - target: log NOP ping timeouts as errors (bsc#1095805).

  - target: split out helper for cxn timeout error stashing
    (bsc#1095805).

  - target: stash sess_err_stats on Data-Out timeout
    (bsc#1095805).

  - target: use ISCSI_IQN_LEN in iscsi_target_stat
    (bsc#1095805).

  - tcp: add tcp_ooo_try_coalesce() helper (bnc#1012382).

  - tcp: call tcp_drop() from tcp_data_queue_ofo()
    (bnc#1012382).

  - tcp: fix a stale ooo_last_skb after a replace
    (bnc#1012382).

  - tcp: free batches of packets in tcp_prune_ofo_queue()
    (bnc#1012382).

  - tcp: increment sk_drops for dropped rx packets
    (bnc#1012382).

  - tcp: use an RB tree for ooo receive queue (bnc#1012382).

  - team: Forbid enslaving team device to itself
    (bnc#1012382).

  - thermal: of-thermal: disable passive polling when
    thermal zone is disabled (bnc#1012382).

  - tools/vm/page-types.c: fix 'defined but not used'
    warning (bnc#1012382).

  - tools/vm/slabinfo.c: fix sign-compare warning
    (bnc#1012382).

  - tpm: Restore functionality to xen vtpm driver
    (bsc#1020645, git-fixes).

  - tsl2550: fix lux1_input error in low light
    (bnc#1012382).

  - ubifs: Check for name being NULL while mounting
    (bnc#1012382).

  - ucma: fix a use-after-free in ucma_resolve_ip()
    (bnc#1012382).

  - USB: fix error handling in usb_driver_claim_interface()
    (bnc#1012382).

  - usb: gadget: fotg210-udc: Fix memory leak of
    fotg210->ep[i] (bnc#1012382).

  - usb: gadget: serial: fix oops when data rx'd after close
    (bnc#1012382).

  - USB: handle NULL config in usb_find_alt_setting()
    (bnc#1012382).

  - USB: remove LPM management from
    usb_driver_claim_interface() (bnc#1012382).

  - USB: serial: kobil_sct: fix modem-status error handling
    (bnc#1012382).

  - USB: serial: simple: add Motorola Tetra MTP6550 id
    (bnc#1012382).

  - USB: usbdevfs: restore warning for nonsensical flags
    (bnc#1012382).

  - USB: usbdevfs: sanitize flags more (bnc#1012382).

  - usb: wusbcore: security: cast sizeof to int for
    comparison (bnc#1012382).

  - USB: yurex: Check for truncation in yurex_read()
    (bnc#1012382).

  - Use make --output-sync feature when available
    (bsc#1012422). The mesages in make output can interleave
    making it impossible to extract warnings reliably. Since
    version 4 GNU Make supports --output-sync flag that
    prints output of each sub-command atomically preventing
    this issue. Detect the flag and use it if available.
    SLE11 has make 3.81 so it is required to include make 4
    in the kernel OBS projects to take advantege of this.

  - Use upstream version of pci-hyperv change 35a88a18d7

  - uwb: hwa-rc: fix memory leak at probe (bnc#1012382).

  - vmci: type promotion bug in qp_host_get_user_memory()
    (bnc#1012382).

  - wlcore: Add missing PM call for
    wlcore_cmd_wait_for_event_or_timeout() (bnc#1012382).

  - wlcore: Fix memory leak in
    wlcore_cmd_wait_for_event_or_timeout (git-fixes).

  - x86/cpufeature: deduplicate X86_FEATURE_L1TF_PTEINV
    (kabi).

  - x86/entry/64: Add two more instruction suffixes
    (bnc#1012382).

  - x86/entry/64: Clear registers for exceptions/interrupts,
    to reduce speculation attack surface (bsc#1105931).

  - x86/entry/64: sanitize extra registers on syscall entry
    (bsc#1105931).

  - x86/fpu: Finish excising 'eagerfpu' (bnc#1012382).

  - x86/fpu: Remove second definition of fpu in
    __fpu__restore_sig() (bsc#1110006).

  - x86/fpu: Remove struct fpu::counter (bnc#1012382).

  - x86/fpu: Remove use_eager_fpu() (bnc#1012382).

  - x86/irq: implement
    irq_data_get_effective_affinity_mask() for v4.12
    (bsc#1109772).

  - x86/kexec: Correct KEXEC_BACKUP_SRC_END off-by-one error
    (bsc#1114648).

  - x86/numa_emulation: Fix emulated-to-physical node
    mapping (bnc#1012382).

  - x86/paravirt: Fix some warning messages (bnc#1065600).

  - x86/percpu: Fix this_cpu_read() (bsc#1110006).

  - x86,sched: Allow topologies where NUMA nodes share an
    LLC (bsc#1091158, bsc#1101555).

  - x86/spec_ctrl: Fix spec_ctrl reporting (bsc#1106913,
    bsc#1111516).

  - x86/speculation: Apply IBPB more strictly to avoid
    cross-process data leak (bsc#1106913).

  - x86/speculation: Enable cross-hyperthread spectre v2
    STIBP mitigation (bsc#1106913).

  - x86/speculation: Propagate information about RSB filling
    mitigation to sysfs (bsc#1106913).

  - x86/time: Correct the attribute on jiffies' definition
    (bsc#1110006).

  - x86/tsc: Add missing header to tsc_msr.c (bnc#1012382).

  - xen: avoid crash in disable_hotplug_cpu (bnc#1012382
    bsc#1106594 bsc#1042422).

  - xen: fix GCC warning and remove duplicate
    EVTCHN_ROW/EVTCHN_COL usage (bnc#1012382).

  - xen/manage: do not complain about an empty value in
    control/sysrq node (bnc#1012382).

  - xhci: Add missing CAS workaround for Intel Sunrise Point
    xHCI (bnc#1012382).

  - xhci: Do not print a warning when setting link state for
    disabled ports (bnc#1012382).

  - rpm/kernel-binary.spec.in: Add missing export
    BRP_SIGN_FILES (bsc#1115587) The export line was
    accidentally dropped at merging scripts branch, which
    resulted in the invalid module signature."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1076393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1109923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997172"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.162-78.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.162-78.1") ) flag++;

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
