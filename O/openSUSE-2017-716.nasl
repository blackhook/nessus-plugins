#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-716.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101127);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000364", "CVE-2017-1000380", "CVE-2017-7346", "CVE-2017-9242");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-716) (Stack Clash)");
  script_summary(english:"Check for the openSUSE-2017-716 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.72 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-1000364: An issue was discovered in the size of
    the stack guard page on Linux, specifically a 4k stack
    guard page is not sufficiently large and can be 'jumped'
    over (the stack guard page is bypassed), this affects
    Linux Kernel versions 4.11.5 and earlier (the stackguard
    page was introduced in 2010) (bnc#1039348).

  - CVE-2017-1000380: sound/core/timer.c in the Linux kernel
    is vulnerable to a data race in the ALSA /dev/snd/timer
    driver resulting in local users being able to read
    information belonging to other users, i.e.,
    uninitialized memory contents may be disclosed when a
    read and an ioctl happen at the same time (bnc#1044125).

  - CVE-2017-7346: The vmw_gb_surface_define_ioctl function
    in drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel did not validate certain levels data, which
    allowed local users to cause a denial of service (system
    hang) via a crafted ioctl call for a /dev/dri/renderD*
    device (bnc#1031796).

  - CVE-2017-9242: The __ip6_append_data function in
    net/ipv6/ip6_output.c in the Linux kernel is too late in
    checking whether an overwrite of an skb data structure
    may occur, which allowed local users to cause a denial
    of service (system crash) via crafted system calls
    (bnc#1041431).

The following non-security bugs were fixed :

  - ASoC: Intel: Skylake: Uninitialized variable in
    probe_codec() (bsc#1043231).

  - IB/core: Fix kernel crash during fail to initialize
    device (bsc#1022595 FATE#322350).

  - IB/core: For multicast functions, verify that LIDs are
    multicast LIDs (bsc#1022595 FATE#322350).

  - IB/core: If the MGID/MLID pair is not on the list return
    an error (bsc#1022595 FATE#322350).

  - IB/ipoib: Fix deadlock between ipoib_stop and mcast join
    flow (bsc#1022595 FATE#322350).

  - Make __xfs_xattr_put_listen preperly report errors
    (bsc#1041242).

  - NFS: Fix an LOCK/OPEN race when unlinking an open file
    (git-fixes).

  - NFSv4: Fix the underestimation of delegation XDR space
    reservation (git-fixes).

  - NFSv4: fix a reference leak caused WARNING messages
    (git-fixes).

  - PM / QoS: Fix memory leak on resume_latency.notifiers
    (bsc#1043231).

  - SUNRPC: Silence WARN_ON when NFSv4.1 over RDMA is in use
    (git-fixes).

  - SUNRPC: ensure correct error is reported by
    xs_tcp_setup_socket() (git-fixes).

  - Update patches.fixes/xen-silence-efi-error-messge.patch
    (bnc#1039900).

  - [media] vb2: Fix an off by one error in
    'vb2_plane_vaddr' (bsc#1043231).

  - bcache: fix calling ida_simple_remove() with incorrect
    minor (bsc#1038085).

  - bna: add missing per queue ethtool stat (bsc#966321
    FATE#320156).

  - bna: integer overflow bug in debugfs (bsc#966321
    FATE#320156).

  - bonding: avoid defaulting hard_header_len to ETH_HLEN on
    slave removal (bsc#1042286).

  - bonding: do not use stale speed and duplex information
    (bsc#1042286).

  - bonding: prevent out of bound accesses (bsc#1042286).

  - brcmfmac: add fallback for devices that do not report
    per-chain values (bsc#1043231).

  - brcmfmac: avoid writing channel out of allocated array
    (bsc#1043231).

  - ceph: fix potential use-after-free (bsc#1043371).

  - ceph: memory leak in ceph_direct_read_write callback
    (bsc#1041810).

  - cfq-iosched: fix the delay of cfq_group's vdisktime
    under iops mode (bsc#1012829).

  - cgroup: remove redundant cleanup in css_create
    (bsc#1012829).

  - cifs: small underflow in cnvrtDosUnixTm() (bnc#1043935).

  - drm/mgag200: Fix to always set HiPri for G200e4
    (bsc#1015452, bsc#995542).

  - drm/nouveau/tmr: fully separate alarm execution/pending
    lists (bsc#1043467).

  - efi: Do not issue error message when booted under Xen
    (bnc#1036638).

  - ext4: fix data corruption for mmap writes (bsc#1012829).

  - ext4: fix data corruption with EXT4_GET_BLOCKS_ZERO
    (bsc#1012829).

  - fuse: fix clearing suid, sgid for chown() (bsc#1012829).

  - ibmvnic: Check adapter state during ibmvnic_poll
    (fate#322021, bsc#1040855).

  - ibmvnic: Deactivate RX pool buffer replenishment on
    H_CLOSED (fate#322021, bsc#1040855).

  - ibmvnic: Fix cleanup of SKB's on driver close
    (fate#322021, bsc#1040855).

  - ibmvnic: Halt TX and report carrier off on H_CLOSED
    return code (fate#322021, bsc#1040855).

  - ibmvnic: Handle failover after failed init crq
    (fate#322021, bsc#1040855).

  - ibmvnic: Non-fatal error handling (fate#322021,
    bsc#1040855).

  - ibmvnic: Reset sub-crqs during driver reset
    (fate#322021, bsc#1040855).

  - ibmvnic: Reset the CRQ queue during driver reset
    (fate#322021, bsc#1040855).

  - ibmvnic: Reset tx/rx pools on driver reset (fate#322021,
    bsc#1040855).

  - ibmvnic: Return failure on attempted mtu change
    (bsc#1043236).

  - ibmvnic: Send gratuitous arp on reset (fate#322021,
    bsc#1040855).

  - ibmvnic: Track state of adapter napis (fate#322021,
    bsc#1040855).

  - ipv6: Do not use ufo handling on later transformed
    packets (bsc#1042286).

  - ipv6: fix endianness error in icmpv6_err (bsc#1042286).

  - kABI: protect struct fib_info (kabi).

  - kABI: protect struct pglist_data (kabi).

  - kABI: protect struct xlog (bsc#1043598).

  - kernel-binary.spec: Propagate MAKE_ARGS to %build
    (bsc#1012422)

  - l2tp: fix race in l2tp_recv_common() (bsc#1042286).

  - libceph: NULL deref on crush_decode() error path
    (bsc#1044015).

  - md: allow creation of mdNNN arrays via
    md_mod/parameters/new_array (bsc#1032339).

  - md: support disabling of create-on-open semantics
    (bsc#1032339).

  - mm/hugetlb: check for reserved hugepages during memory
    offline (bnc#971975 VM -- git fixes).

  - mm/hugetlb: fix incorrect hugepages count during mem
    hotplug (bnc#971975 VM -- git fixes).

  - mmc: Downgrade error level (bsc#1042536).

  - module: fix memory leak on early load_module() failures
    (bsc#1043014).

  - net: bridge: start hello timer only if device is up
    (bnc#1012382).

  - net: fix compile error in skb_orphan_partial()
    (bnc#1012382).

  - net: ipv6: set route type for anycast routes
    (bsc#1042286).

  - netfilter: nf_conntrack_sip: extend request line
    validation (bsc#1042286).

  - netfilter: nf_ct_expect: remove the redundant slash when
    policy name is empty (bsc#1042286).

  - netfilter: nf_dup_ipv6: set again FLOWI_FLAG_KNOWN_NH at
    flowi6_flags (bsc#1042286).

  - netfilter: nf_nat_snmp: Fix panic when snmp_trap_helper
    fails to register (bsc#1042286).

  - netfilter: nfnetlink_queue: reject verdict request from
    different portid (bsc#1042286).

  - netfilter: restart search if moved to other chain
    (bsc#1042286).

  - netfilter: use fwmark_reflect in nf_send_reset
    (bsc#1042286).

  - netxen_nic: set rcode to the return status from the call
    to netxen_issue_cmd (bsc#966339 FATE#320150).

  - nfs: Fix 'Do not increment lock sequence ID after
    NFS4ERR_MOVED' (git-fixes).

  - nsfs: mark dentry with DCACHE_RCUACCESS (bsc#1012829).

  - nvme: submit nvme_admin_activate_fw to admin queue
    (bsc#1044532).

  - percpu: remove unused chunk_alloc parameter from
    pcpu_get_pages() (bnc#971975 VM -- git fixes).

  - perf/x86/intel/rapl: Make Knights Landings support
    functional (bsc#1042517).

  - powerpc/64: Fix flush_(d|i)cache_range() called from
    modules (bnc#863764 fate#315275, LTC#103998).

  - quota: fill in Q_XGETQSTAT inode information for
    inactive quotas (bsc#1042356).

  - radix-tree: fix radix_tree_iter_retry() for tagged
    iterators (bsc#1012829).

  - rpm/kernel-binary.spec: remove superfluous flags This
    should make build logs more readable and people adding
    more flags should have easier time finding a place to
    add them in the spec file.

  - rpm/kernel-spec-macros: Fix the check if there is no
    rebuild counter (bsc#1012060)

  - rtnl: reset calcit fptr in rtnl_unregister()
    (bsc#1042286).

  - series.conf: remove silly comment

  - tcp: account for ts offset only if tsecr not zero
    (bsc#1042286).

  - tcp: fastopen: accept data/FIN present in SYNACK message
    (bsc#1042286).

  - tcp: fastopen: avoid negative sk_forward_alloc
    (bsc#1042286).

  - tcp: fastopen: call tcp_fin() if FIN present in SYNACK
    (bsc#1042286).

  - tcp: fastopen: fix rcv_wup initialization for TFO server
    on SYN/data (bsc#1042286).

  - tpm: Downgrade error level (bsc#1042535).

  - udp: avoid ufo handling on IP payload compression
    packets (bsc#1042286).

  - udplite: call proper backlog handlers (bsc#1042286).

  - x86/PCI: Mark Broadwell-EP Home Agent 1 as having
    non-compliant BARs (bsc#9048891).

  - xen/mce: do not issue error message for failed
    /dev/mcelog registration (bnc#1036638).

  - xen: add sysfs node for guest type (bnc#1037840).

  - xfrm: Fix memory leak of aead algorithm name
    (bsc#1042286).

  - xfs: add missing include dependencies to xfs_dir2.h
    (bsc#1042421).

  - xfs: do not warn on buffers not being recovered due to
    LSN (bsc#1043598).

  - xfs: fix xfs_mode_to_ftype() prototype (bsc#1043598).

  - xfs: log recovery tracepoints to track current lsn and
    buffer submission (bsc#1043598).

  - xfs: pass current lsn to log recovery buffer validation
    (bsc#1043598).

  - xfs: refactor log record unpack and data processing
    (bsc#1043598).

  - xfs: replace xfs_mode_to_ftype table with switch
    statement (bsc#1042421).

  - xfs: rework log recovery to submit buffers on LSN
    boundaries (bsc#1043598).

  - xfs: rework the inline directory verifiers
    (bsc#1042421).

  - xfs: sanity check directory inode di_size (bsc#1042421).

  - xfs: sanity check inode di_mode (bsc#1042421).

  - xfs: update metadata LSN in buffers during log recovery
    (bsc#1043598).

  - xfs: verify inline directory data forks (bsc#1042421).

  - zswap: do not param_set_charp while holding spinlock (VM
    Functionality, bsc#1042886)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012060"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1015452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=863764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995542"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'rsh_stack_clash_priv_esc.rb');
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.72-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.72-18.12.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.72-18.12.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.72-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.72-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.72-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.72-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.72-18.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.72-18.12.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.72-18.12.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
