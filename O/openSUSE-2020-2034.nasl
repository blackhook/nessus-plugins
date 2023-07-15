#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2034.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(143314);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-25669",
    "CVE-2020-25704",
    "CVE-2020-25705",
    "CVE-2020-28915"
  );
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-2034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The openSUSE Leap 15.1 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2020-28915: A buffer over-read (at the framebuffer
    layer) in the fbcon code could be used by local
    attackers to read kernel memory, aka CID-6735b4632def
    (bnc#1178886).

  - CVE-2020-25669: A use-after-free in teardown paths of
    sunkbd was fixed (bsc#1178182).

  - CVE-2020-25705: A flaw in the way reply ICMP packets are
    limited in the Linux kernel functionality was found that
    allowed to quickly scan open UDP ports. This flaw
    allowed an off-path remote user to effectively bypassing
    source port UDP randomization. The highest threat from
    this vulnerability is to confidentiality and possibly
    integrity, because software that relies on UDP source
    port randomization are indirectly affected as well.
    Kernel versions may be vulnerable to this issue
    (bnc#1175721 bnc#1178782).

  - CVE-2020-25704: A a memory leak in
    perf_event_parse_addr_filter() was foxed (bsc#1178393,
    CVE-2020-25704).

The following non-security bugs were fixed :

  - ACPI: NFIT: Fix comparison to '-ENXIO' (git-fixes).

  - bpf: Zero-fill re-used per-cpu map element (git-fixes).

  - can: af_can: prevent potential access of uninitialized
    member in canfd_rcv() (git-fixes).

  - can: af_can: prevent potential access of uninitialized
    member in can_rcv() (git-fixes).

  - can: dev: can_restart(): post buffer from the right
    context (git-fixes).

  - can: m_can: m_can_handle_state_change(): fix state
    change (git-fixes).

  - can: m_can: m_can_stop(): set device to software init
    mode before closing (git-fixes).

  - can: mcba_usb: mcba_usb_start_xmit(): first fill skb,
    then pass to can_put_echo_skb() (git-fixes).

  - can: peak_usb: fix potential integer overflow on shift
    of a int (git-fixes).

  - docs: ABI: sysfs-c2port: remove a duplicated entry
    (git-fixes).

  - drbd: code cleanup by using sendpage_ok() to check page
    for kernel_sendpage() (bsc#1172873).

  - drm/i915: Break up error capture compression loops with
    cond_resched() (git-fixes).

  - drm/vc4: drv: Add error handding for bind (git-fixes).

  - Drop sysctl files for dropped archs, add ppc64le and
    arm64 (bsc#1178838). Also fix the ppc64 page size.

  - fs/proc/array.c: allow reporting eip/esp for all
    coredumping threads (bsc#1050549).

  - ftrace: Fix recursion check for NMI test (git-fixes).

  - ftrace: Handle tracing when switching between context
    (git-fixes).

  - futex: Do not enable IRQs unconditionally in
    put_pi_state() (bsc#1067665).

  - futex: Handle transient 'ownerless' rtmutex state
    correctly (bsc#1067665).

  - hv_netvsc: Add XDP support (bsc#1177819, bsc#1177820).

  - hv_netvsc: deal with bpf API differences in 4.12
    (bsc#1177819, bsc#1177820).

  - hv_netvsc: Fix XDP refcnt for synthetic and VF NICs
    (bsc#1177819, bsc#1177820).

  - hv_netvsc: make recording RSS hash depend on feature
    flag (bsc#1178853, bsc#1178854).

  - hv_netvsc: record hardware hash in skb (bsc#1178853,
    bsc#1178854).

  - hyperv_fb: Update screen_info after removing old
    framebuffer (bsc#1175306).

  - inet_diag: Fix error path to cancel the meseage in
    inet_req_diag_fill() (git-fixes).

  - Input: adxl34x - clean up a data type in adxl34x_probe()
    (git-fixes).

  - kthread_worker: prevent queuing delayed work from
    timer_fn when it is being canceled (git-fixes).

  - libceph: use sendpage_ok() in ceph_tcp_sendpage()
    (bsc#1172873).

  - locking/lockdep: Add debug_locks check in
    __lock_downgrade() (bsc#1050549).

  - locking/percpu-rwsem: Use this_cpu_(inc,dec)() for
    read_count (bsc#1050549).

  - locktorture: Print ratio of acquisitions, not failures
    (bsc#1050549).

  - mac80211: minstrel: fix tx status processing corner case
    (git-fixes).

  - mac80211: minstrel: remove deferred sampling code
    (git-fixes).

  - memcg: fix NULL pointer dereference in
    __mem_cgroup_usage_unregister_event (bsc#1177703).

  - mmc: sdhci-of-esdhc: Handle pulse width detection
    erratum for more SoCs (git-fixes).

  - mm/memcg: fix refcount error while moving and swapping
    (bsc#1178686).

  - net: add WARN_ONCE in kernel_sendpage() for improper
    zero-copy send (bsc#1172873).

  - net: ena: Capitalize all log strings and improve code
    readability (bsc#1177397).

  - net: ena: Change license into format to SPDX in all
    files (bsc#1177397).

  - net: ena: Change log message to netif/dev function
    (bsc#1177397).

  - net: ena: Change RSS related macros and variables names
    (bsc#1177397).

  - net: ena: ethtool: Add new device statistics
    (bsc#1177397).

  - net: ena: ethtool: add stats printing to XDP queues
    (bsc#1177397).

  - net: ena: ethtool: convert stat_offset to 64 bit
    resolution (bsc#1177397).

  - net: ena: Fix all static chekers' warnings
    (bsc#1177397).

  - net: ena: Remove redundant print of placement policy
    (bsc#1177397).

  - net: ena: xdp: add queue counters for xdp actions
    (bsc#1177397).

  - netfilter: nat: can't use dst_hold on noref dst
    (bsc#1178878).

  - net: introduce helper sendpage_ok() in
    include/linux/net.h (bsc#1172873). kABI workaround for
    including mm.h in include/linux/net.h (bsc#1172873).

  - net/mlx4_core: Fix init_hca fields offset (git-fixes).

  - net: usb: qmi_wwan: add Telit LE910Cx 0x1230 composition
    (git-fixes).

  - NFSv4.1: fix handling of backchannel binding in
    BIND_CONN_TO_SESSION (bsc#1170630).

  - nvme-tcp: check page by sendpage_ok() before calling
    kernel_sendpage() (bsc#1172873).

  - pinctrl: intel: Set default bias in case no particular
    value given (git-fixes).

  - powerpc/pseries/cpuidle: add polling idle for shared
    processor guests (bsc#1178765 ltc#188968).

  - powerpc/vnic: Extend 'failover pending' window
    (bsc#1176855 ltc#187293).

  - powerpc/vnic: Extend 'failover pending' window
    (bsc#1176855 ltc#187293).

  - regulator: avoid resolve_supply() infinite recursion
    (git-fixes).

  - regulator: fix memory leak with repeated
    set_machine_constraints() (git-fixes).

  - regulator: ti-abb: Fix array out of bound read access on
    the first transition (git-fixes).

  - regulator: workaround self-referent regulators
    (git-fixes).

  - Revert 'cdc-acm: hardening against malicious devices'
    (git-fixes).

  - ring-buffer: Fix recursion protection transitions
    between interrupt context (git-fixes).

  - scsi: libiscsi: use sendpage_ok() in
    iscsi_tcp_segment_map() (bsc#1172873).

  - scsi: lpfc: Fix initial FLOGI failure due to BBSCN not
    supported (git-fixes).

  - thunderbolt: Add the missed ida_simple_remove() in
    ring_request_msix() (git-fixes).

  - time: Prevent undefined behaviour in timespec64_to_ns()
    (git-fixes).

  - USB: Add NO_LPM quirk for Kingston flash drive
    (git-fixes).

  - usb: core: driver: fix stray tabs in error messages
    (git-fixes).

  - usb: host: ehci-tegra: Fix error handling in
    tegra_ehci_probe() (git-fixes).

  - USB: serial: cyberjack: fix write-URB completion race
    (git-fixes).

  - USB: serial: ftdi_sio: add support for FreeCalypso
    JTAG+UART adapters (git-fixes).

  - USB: serial: option: add Cellient MPL200 card
    (git-fixes).

  - USB: serial: option: add LE910Cx compositions 0x1203,
    0x1230, 0x1231 (git-fixes).

  - USB: serial: option: add Quectel EC200T module support
    (git-fixes).

  - USB: serial: option: add Telit FN980 composition 0x1055
    (git-fixes).

  - USB: serial: option: Add Telit FT980-KS composition
    (git-fixes).

  - USB: serial: pl2303: add device-id for HP GC device
    (git-fixes).

  - video: hyperv: hyperv_fb: Obtain screen resolution from
    Hyper-V host (bsc#1175306).

  - video: hyperv: hyperv_fb: Support deferred IO for
    Hyper-V frame buffer driver (bsc#1175306).

  - video: hyperv: hyperv_fb: Use physical memory for fb on
    HyperV Gen 1 VMs (bsc#1175306).

  - vt: Disable KD_FONT_OP_COPY (bsc#1178589).

  - x86/kexec: Use up-to-dated screen_info copy to fill boot
    params (bsc#1175306).

  - xfs: fix a missing unlock on error in xfs_fs_map_blocks
    (git-fixes).

  - xfs: fix flags argument to rmap lookup when converting
    shared file rmaps (git-fixes).

  - xfs: fix rmap key and record comparison functions
    (git-fixes).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927455");
  script_set_attribute(attribute:"solution", value:
"Update the affected the Linux Kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25669");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.83.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.83.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
