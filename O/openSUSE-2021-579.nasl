#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-579.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149605);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-36310", "CVE-2020-36311", "CVE-2020-36312", "CVE-2020-36322", "CVE-2021-28950", "CVE-2021-29154", "CVE-2021-30002", "CVE-2021-3483");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2021-579)");
  script_summary(english:"Check for the openSUSE-2021-579 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The openSUSE Linux Leap 15.2 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2021-3483: Fixed a use-after-free in nosy.c
    (bsc#1184393).

  - CVE-2021-30002: Fixed a memory leak for large arguments
    in video_usercopy (bsc#1184120).

  - CVE-2021-29154: Fixed incorrect computation of branch
    displacements, allowing arbitrary code execution
    (bsc#1184391).

  - CVE-2021-28950: Fixed an issue in fs/fuse/fuse_i.h due
    to a retry loop continually was finding the same bad
    inode (bsc#1184194).

  - CVE-2020-36312: Fixed a memory leak upon a kmalloc
    failure (bsc#1184509 ).

  - CVE-2020-36311: Fixed a denial of service (soft lockup)
    by triggering destruction of a large SEV VM
    (bsc#1184511).

  - CVE-2020-36310: Fixed infinite loop for certain nested
    page faults (bsc#1184512).

  - CVE-2020-25670, CVE-2020-25671, CVE-2020-25672,
    CVE-2020-25673: Fixed multiple bugs in NFC subsytem
    (bsc#1178181).

  - CVE-2020-36322: Fixed an issue was discovered in FUSE
    filesystem implementation which could have caused a
    system crash (bsc#1184211).

The following non-security bugs were fixed :

  - ALSA: aloop: Fix initialization of controls (git-fixes).

  - ALSA: hda/realtek: Fix speaker amp setup on Acer Aspire
    E1 (git-fixes).

  - appletalk: Fix skb allocation size in loopback case
    (git-fixes).

  - ASoC: cygnus: fix for_each_child.cocci warnings
    (git-fixes).

  - ASoC: fsl_esai: Fix TDM slot setup for I2S mode
    (git-fixes).

  - ASoC: intel: atom: Remove 44100 sample-rate from the
    media and deep-buffer DAI descriptions (git-fixes).

  - ASoC: intel: atom: Stop advertising non working S24LE
    support (git-fixes).

  - ASoC: max98373: Added 30ms turn on/off time delay
    (git-fixes).

  - ASoC: sunxi: sun4i-codec: fill ASoC card owner
    (git-fixes).

  - ASoC: wm8960: Fix wrong bclk and lrclk with pll enabled
    for some chips (git-fixes).

  - ath10k: hold RCU lock when calling
    ieee80211_find_sta_by_ifaddr() (git-fixes).

  - atl1c: fix error return code in atl1c_probe()
    (git-fixes).

  - atl1e: fix error return code in atl1e_probe()
    (git-fixes).

  - batman-adv: initialize 'struct
    batadv_tvlv_tt_vlan_data'->reserved field (git-fixes).

  - bpf: Fix verifier jsgt branch analysis on max bound
    (bsc#1155518).

  - bpf: Remove MTU check in __bpf_skb_max_len
    (bsc#1155518).

  - bpf, sockmap: Fix sk->prot unhash op reset
    (bsc#1155518).

  - brcmfmac: clear EAP/association status bits on linkdown
    events (git-fixes).

  - bus: ti-sysc: Fix warning on unbind if reset is not
    deasserted (git-fixes).

  - cifs: change noisy error message to FYI (bsc#1181507).

  - cifs_debug: use %pd instead of messing with ->d_name
    (bsc#1181507).

  - cifs: do not send close in compound create+close
    requests (bsc#1181507).

  - cifs: New optype for session operations (bsc#1181507).

  - cifs: print MIDs in decimal notation (bsc#1181507).

  - cifs: return proper error code in statfs(2)
    (bsc#1181507).

  - cifs: Tracepoints and logs for tracing credit changes
    (bsc#1181507).

  - clk: fix invalid usage of list cursor in register
    (git-fixes).

  - clk: fix invalid usage of list cursor in unregister
    (git-fixes).

  - clk: socfpga: fix iomem pointer cast on 64-bit
    (git-fixes).

  - dm mpath: switch paths in dm_blk_ioctl() code path
    (bsc#1167574, bsc#1175995, bsc#1184485).

  - drivers: video: fbcon: fix NULL dereference in
    fbcon_cursor() (git-fixes).

  - drm/amdgpu: check alignment on CPU page for bo map
    (git-fixes).

  - drm/amdgpu: fix offset calculation in
    amdgpu_vm_bo_clear_mappings() (git-fixes).

  - drm/i915: Fix invalid access to ACPI _DSM objects
    (bsc#1184074).

  - drm/msm/adreno: a5xx_power: Do not apply A540 lm_setup
    to other GPUs (git-fixes).

  - drm/msm: Ratelimit invalid-fence message (git-fixes).

  - drm/msm: Set drvdata to NULL when msm_drm_init() fails
    (git-fixes).

  - enetc: Fix reporting of h/w packet counters (git-fixes).

  - fix Patch-mainline:
    patches.suse/cifs_debug-use-pd-instead-of-messing-with-d
    _name.patch

  - fix patch metadata

  - fuse: fix bad inode (bsc#1184211).

  - fuse: fix live lock in fuse_iget() (bsc#1184211).

  - gianfar: Handle error code at MAC address change
    (git-fixes).

  - i40e: Fix parameters in aq_get_phy_register()
    (jsc#SLE-8025).

  - i40e: Fix sparse error: 'vsi->netdev' could be null
    (jsc#SLE-8025).

  - ice: remove DCBNL_DEVRESET bit from PF state
    (jsc#SLE-7926).

  - iommu/vt-d: Use device numa domain if RHSA is missing
    (bsc#1184585).

  - kABI: powerpc/pmem: Include pmem prototypes (bsc#1113295
    git-fixes).

  - libbpf: Fix INSTALL flag order (bsc#1155518).

  - libbpf: Only create rx and tx XDP rings when necessary
    (bsc#1155518).

  - locking/mutex: Fix non debug version of
    mutex_lock_io_nested() (git-fixes).

  - mac80211: choose first enabled channel for monitor
    (git-fixes).

  - mac80211: fix TXQ AC confusion (git-fixes).

  - mISDN: fix crash in fritzpci (git-fixes).

  - net: atheros: switch from 'pci_' to 'dma_' API
    (git-fixes).

  - net: b44: fix error return code in b44_init_one()
    (git-fixes).

  - net: ethernet: ti: cpsw: fix error return code in
    cpsw_probe() (git-fixes).

  - net: hns3: Remove the left over redundant check &
    assignment (bsc#1154353).

  - net: lantiq: Wait for the GPHY firmware to be ready
    (git-fixes).

  - net/mlx5: Fix PPLM register mapping (jsc#SLE-8464).

  - net: pasemi: fix error return code in pasemi_mac_open()
    (git-fixes).

  - net: phy: broadcom: Only advertise EEE for supported
    modes (git-fixes).

  - net: qualcomm: rmnet: Fix incorrect receive packet
    handling during cleanup (git-fixes).

  - net: sched: disable TCQ_F_NOLOCK for pfifo_fast
    (bsc#1183405)

  - net: wan/lmc: unregister device when no matching device
    is found (git-fixes).

  - platform/x86: intel-hid: Support Lenovo ThinkPad X1
    Tablet Gen 2 (git-fixes).

  - platform/x86: thinkpad_acpi: Allow the FnLock LED to
    change state (git-fixes).

  - PM: runtime: Fix ordering in pm_runtime_get_suppliers()
    (git-fixes).

  - post.sh: Return an error when module update fails
    (bsc#1047233 bsc#1184388).

  - powerpc/64s: Fix instruction encoding for lis in
    ppc_function_entry() (bsc#1065729).

  - powerpc/pmem: Include pmem prototypes (bsc#1113295
    git-fixes).

  - powerpc/pseries/ras: Remove unused variable 'status'
    (bsc#1065729).

  - powerpc/sstep: Check instruction validity against ISA
    version before emulation (bsc#1156395).

  - powerpc/sstep: Fix darn emulation (bsc#1156395).

  - powerpc/sstep: Fix incorrect return from analyze_instr()
    (bsc#1156395).

  - powerpc/sstep: Fix load-store and update emulation
    (bsc#1156395).

  - qlcnic: fix error return code in
    qlcnic_83xx_restart_hw() (git-fixes).

  - RAS/CEC: Correct ce_add_elem()'s returned values
    (bsc#1152489).

  - regulator: bd9571mwv: Fix AVS and DVFS voltage range
    (git-fixes).

  - rpm/check-for-config-changes: Also ignore AS_VERSION
    added in 5.12.

  - rpm/kernel-binary.spec.in: Fix dependency of
    kernel-*-devel package (bsc#1184514) The devel package
    requires the kernel binary package itself for building
    modules externally.

  - samples/bpf: Fix possible hang in xdpsock with multiple
    threads (bsc#1155518).

  - scsi: ibmvfc: Fix invalid state machine BUG_ON()
    (bsc#1184647 ltc#191231).

  - smb3: add dynamic trace point to trace when credits
    obtained (bsc#1181507).

  - smb3: fix crediting for compounding when only one
    request in flight (bsc#1181507).

  - soc/fsl: qbman: fix conflicting alignment attributes
    (git-fixes).

  - staging: comedi: cb_pcidas64: fix request_irq() warn
    (git-fixes).

  - staging: comedi: cb_pcidas: fix request_irq() warn
    (git-fixes).

  - thermal/core: Add NULL pointer check before using
    cooling device stats (git-fixes).

  - USB: cdc-acm: downgrade message to debug (git-fixes).

  - USB: cdc-acm: untangle a circular dependency between
    callback and softint (git-fixes).

  - usbip: vhci_hcd fix shift out-of-bounds in
    vhci_hub_control() (git-fixes).

  - USB: quirks: ignore remote wake-up on Fibocom L850-GL
    LTE modem (git-fixes).

  - x86: Introduce TS_COMPAT_RESTART to fix
    get_nr_restart_syscall() (bsc#1152489).

  - x86/ioapic: Ignore IRQ2 again (bsc#1152489).

  - x86/mem_encrypt: Correct physical address calculation in
    __set_clr_pte_enc() (bsc#1152489).

  - xen/events: fix setting irq affinity (bsc#1184583)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1113295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184647"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-rebuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-preempt-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debuginfo-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-debugsource-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-debug-devel-debuginfo-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-5.3.18-lp152.72.1.lp152.8.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-base-rebuild-5.3.18-lp152.72.1.lp152.8.30.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debuginfo-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-debugsource-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-default-devel-debuginfo-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-devel-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-docs-html-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debuginfo-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-debugsource-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-kvmsmall-devel-debuginfo-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-macros-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-build-debugsource-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-obs-qa-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debuginfo-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-debugsource-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-preempt-devel-debuginfo-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-source-vanilla-5.3.18-lp152.72.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"kernel-syms-5.3.18-lp152.72.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-debuginfo / kernel-debug-debugsource / etc");
}
