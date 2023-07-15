#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1062.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103287);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000251", "CVE-2017-11472", "CVE-2017-12134", "CVE-2017-14051", "CVE-2017-14106");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-1062) (BlueBorne)");
  script_summary(english:"Check for the openSUSE-2017-1062 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.87 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2017-1000251: The native Bluetooth stack in the
    Linux Kernel (BlueZ) was vulnerable to a stack overflow
    vulnerability in the processing of L2CAP configuration
    responses resulting in Remote code execution in kernel
    space (bnc#1057389).

  - CVE-2017-14106: The tcp_disconnect function in
    net/ipv4/tcp.c in the Linux kernel allowed local users
    to cause a denial of service (__tcp_select_window
    divide-by-zero error and system crash) by triggering a
    disconnect within a certain tcp_recvmsg code path
    (bnc#1056982).

  - CVE-2017-11472: The acpi_ns_terminate() function in
    drivers/acpi/acpica/nsutils.c in the Linux kernel did
    not flush the operand cache and causes a kernel stack
    dump, which allowed local users to obtain sensitive
    information from kernel memory and bypass the KASLR
    protection mechanism (in the kernel through 4.9) via a
    crafted ACPI table (bnc#1049580).

  - CVE-2017-14051: An integer overflow in the
    qla2x00_sysfs_write_optrom_ctl function in
    drivers/scsi/qla2xxx/qla_attr.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash) by leveraging root access
    (bnc#1056588).

  - CVE-2017-12134: The xen_biovec_phys_mergeable function
    in drivers/xen/biomerge.c in Xen might allow local OS
    guest users to corrupt block device data streams and
    consequently obtain sensitive memory information, cause
    a denial of service, or gain host OS privileges by
    leveraging incorrect block IO merge-ability calculation
    (bnc#1051790 1053919).

The following non-security bugs were fixed :

  - acpi / scan: Prefer devices without _HID for _ADR
    matching (git-fixes).

  - alsa: hda - Add stereo mic quirk for Lenovo G50-70
    (17aa:3978) (bsc#1020657).

  - alsa: hda - Implement mic-mute LED mode enum
    (bsc#1055013).

  - alsa: hda/realtek - Add support headphone Mic for ALC221
    of HP platform (bsc#1024405).

  - alsa: ice1712: Add support for STAudio ADCIII
    (bsc#1048934).

  - alsa: usb-audio: Apply sample rate quirk to Sennheiser
    headset (bsc#1052580).

  - Add 'shutdown' to 'struct class' (bsc#1053117).

  - bluetooth: bnep: fix possible might sleep error in
    bnep_session (bsc#1031784).

  - bluetooth: cmtp: fix possible might sleep error in
    cmtp_session (bsc#1031784).

  - btrfs: fix early ENOSPC due to delalloc (bsc#1049226).

  - nfs: flush data when locking a file to ensure cache
    coherence for mmap (bsc#981309).

  - Revert '/proc/iomem: only expose physical resource
    addresses to privileged users' (kabi).

  - Revert 'Make file credentials available to the seqfile
    interfaces' (kabi).

  - usb: core: fix device node leak (bsc#1047487).

  - Update
    patches.drivers/tpm-141-fix-RC-value-check-in-tpm2_seal_
    trusted.patch (bsc#1020645, fate#321435, fate#321507,
    fate#321600, bsc#1034048, git-fixes 5ca4c20cfd37).

  - bnxt: add a missing rcu synchronization (bnc#1038583).

  - bnxt: do not busy-poll when link is down (bnc#1038583).

  - bnxt_en: Enable MRU enables bit when configuring VNIC
    MRU (bnc#1038583).

  - bnxt_en: Fix 'uninitialized variable' bug in TPA code
    path (bnc#1038583).

  - bnxt_en: Fix NULL pointer dereference in a failure path
    during open (bnc#1038583).

  - bnxt_en: Fix NULL pointer dereference in reopen failure
    path (bnc#1038583).

  - bnxt_en: Fix TX push operation on ARM64 (bnc#1038583).

  - bnxt_en: Fix VF virtual link state (bnc#1038583).

  - bnxt_en: Fix a VXLAN vs GENEVE issue (bnc#1038583).

  - bnxt_en: Fix and clarify link_info->advertising
    (bnc#1038583).

  - bnxt_en: Fix ring arithmetic in bnxt_setup_tc()
    (bnc#1038583).

  - bnxt_en: Pad TX packets below 52 bytes (bnc#1038583).

  - bnxt_en: Refactor TPA code path (bnc#1038583).

  - bnxt_en: fix pci cleanup in bnxt_init_one() failure path
    (bnc#1038583).

  - bnxt_en: initialize rc to zero to avoid returning
    garbage (bnc#1038583).

  - ceph: fix readpage from fscache (bsc#1057015).

  - cxgb4: Fix stack out-of-bounds read due to wrong size to
    t4_record_mbox() (bsc#1021424 bsc#1022743).

  - drivers: net: xgene: Fix wrong logical operation
    (bsc#1056827).

  - drm/vmwgfx: Limit max desktop dimensions to 8Kx8K
    (bsc#1048155).

  - fuse: initialize the flock flag in fuse_file on
    allocation (git-fixes).

  - gfs2: Do not clear SGID when inheriting ACLs
    (bsc#1012829).

  - ibmvnic: Clean up resources on probe failure
    (fate#323285, bsc#1058116).

  - iwlwifi: missing error code in iwl_trans_pcie_alloc()
    (bsc#1031717).

  - iwlwifi: mvm: do not send CTDP commands via debugfs if
    not supported (bsc#1031717).

  - kernel/*: switch to memdup_user_nul() (bsc#1048893).

  - lib: test_rhashtable: Fix KASAN warning (bsc#1055359).

  - lib: test_rhashtable: fix for large entry counts
    (bsc#1055359).

  - lightnvm: remove unused rq parameter of
    nvme_nvm_rqtocmd() to kill warning (FATE#319466).

  - md/raid5: fix a race condition in stripe batch
    (linux-stable).

  - mm, madvise: ensure poisoned pages are removed from
    per-cpu lists (VM hw poison -- git fixes).

  - mm/page_alloc.c: apply gfp_allowed_mask before the first
    allocation attempt (bnc#971975 VM -- git fixes).

  - mptsas: Fixup device hotplug for VMware ESXi
    (bsc#1030850).

  - netfilter: fix IS_ERR_VALUE usage (bsc#1052888).

  - netfilter: x_tables: pack percpu counter allocations
    (bsc#1052888).

  - netfilter: x_tables: pass xt_counters struct instead of
    packet counter (bsc#1052888).

  - netfilter: x_tables: pass xt_counters struct to counter
    allocator (bsc#1052888).

  - new helper: memdup_user_nul() (bsc#1048893).

  - of: fix '/cpus' reference leak in
    of_numa_parse_cpu_nodes() (bsc#1056827).

  - ovl: fix dentry leak for default_permissions
    (bsc#1054084).

  - percpu_ref: allow operation mode switching operations to
    be called concurrently (bsc#1055096).

  - percpu_ref: remove unnecessary RCU grace period for
    staggered atomic switching confirmation (bsc#1055096).

  - percpu_ref: reorganize __percpu_ref_switch_to_atomic()
    and relocate percpu_ref_switch_to_atomic()
    (bsc#1055096).

  - percpu_ref: restructure operation mode switching
    (bsc#1055096).

  - percpu_ref: unify staggered atomic switching wait
    behavior (bsc#1055096).

  - rtnetlink: fix rtnl_vfinfo_size (bsc#1056261).

  - s390: export symbols for crash-kmp (bsc#1053915).

  - supported.conf: clear mistaken external support flag for
    cifs.ko (bsc#1053802).

  - sysctl: fix lax sysctl_check_table() sanity check
    (bsc#1048893).

  - sysctl: fold sysctl_writes_strict checks into helper
    (bsc#1048893).

  - sysctl: kdoc'ify sysctl_writes_strict (bsc#1048893).

  - sysctl: simplify unsigned int support (bsc#1048893).

  - tpm: Issue a TPM2_Shutdown for TPM2 devices
    (bsc#1053117).

  - tpm: KABI fix (bsc#1053117).

  - tpm: fix: return rc when devm_add_action() fails
    (bsc#1020645, fate#321435, fate#321507, fate#321600,
    bsc#1034048, git-fixes 8e0ee3c9faed).

  - tpm: read burstcount from TPM_STS in one 32-bit
    transaction (bsc#1020645, fate#321435, fate#321507,
    fate#321600, bsc#1034048, git-fixes 27084efee0c3).

  - tpm_tis_core: Choose appropriate timeout for reading
    burstcount (bsc#1020645, fate#321435, fate#321507,
    fate#321600, bsc#1034048, git-fixes aec04cbdf723).

  - tpm_tis_core: convert max timeouts from msec to jiffies
    (bsc#1020645, fate#321435, fate#321507, fate#321600,
    bsc#1034048, git-fixes aec04cbdf723).

  - tty: serial: msm: Support more bauds (git-fixes).

  - ubifs: Correctly evict xattr inodes (bsc#1012829).

  - ubifs: Do not leak kernel memory to the MTD
    (bsc#1012829).

  - xfs: fix inobt inode allocation search optimization
    (bsc#1012829)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1024405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981309"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/18");
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

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.87-18.29.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.87-18.29.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.87-18.29.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.87-18.29.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
