#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1063.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103288);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000251", "CVE-2017-11472", "CVE-2017-14106");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2017-1063) (BlueBorne)");
  script_summary(english:"Check for the openSUSE-2017-1063 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.3 kernel was updated to 4.4.87 to receive various
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
    protection mechanism via a crafted ACPI table
    (bnc#1049580).

The following non-security bugs were fixed :

  - acpica: IORT: Update SMMU models for revision C
    (bsc#1036060).

  - acpi/nfit: Fix memory corruption/Unregister mce decoder
    on failure (bsc#1057047).

  - ahci: do not use MSI for devices with the silly Intel
    NVMe remapping scheme (bsc#1048912).

  - ahci: thunderx2: stop engine fix update (bsc#1057031).

  - alsa: hda/realtek - Add support headphone Mic for ALC221
    of HP platform (bsc#1024405).

  - arm64: mm: select CONFIG_ARCH_PROC_KCORE_TEXT
    (bsc#1046529).

  - arm64: PCI: Fix struct acpi_pci_root_ops allocation
    failure path (bsc#1056849).

  - arm64: Update config files. Enable ARCH_PROC_KCORE_TEXT

  - blacklist.conf: gcc7 compiler warning (bsc#1056849)

  - bnxt: add a missing rcu synchronization (bnc#1038583).

  - bnxt: do not busy-poll when link is down (bnc#1038583).

  - bnxt_en: Enable MRU enables bit when configuring VNIC
    MRU (bnc#1038583).

  - bnxt_en: Fix and clarify link_info->advertising
    (bnc#1038583).

  - bnxt_en: Fix a VXLAN vs GENEVE issue (bnc#1038583).

  - bnxt_en: Fix NULL pointer dereference in a failure path
    during open (bnc#1038583).

  - bnxt_en: Fix NULL pointer dereference in reopen failure
    path (bnc#1038583).

  - bnxt_en: fix pci cleanup in bnxt_init_one() failure path
    (bnc#1038583).

  - bnxt_en: Fix ring arithmetic in bnxt_setup_tc()
    (bnc#1038583).

  - bnxt_en: Fix TX push operation on ARM64 (bnc#1038583).

  - bnxt_en: Fix 'uninitialized variable' bug in TPA code
    path (bnc#1038583).

  - bnxt_en: Fix VF virtual link state (bnc#1038583).

  - bnxt_en: initialize rc to zero to avoid returning
    garbage (bnc#1038583).

  - bnxt_en: Pad TX packets below 52 bytes (bnc#1038583).

  - bnxt_en: Refactor TPA code path (bnc#1038583).

  - ceph: fix readpage from fscache (bsc#1057015).

  - cifs: add build_path_from_dentry_optional_prefix()
    (fate#323482).

  - cifs: add use_ipc flag to SMB2_ioctl() (fate#323482).

  - cifs: Fix sparse warnings (fate#323482).

  - cifs: implement get_dfs_refer for SMB2+ (fate#323482).

  - cifs: let ses->ipc_tid hold smb2 TreeIds (fate#323482).

  - cifs: move DFS response parsing out of SMB1 code
    (fate#323482).

  - cifs: remove any preceding delimiter from prefix_path
    (fate#323482).

  - cifs: set signing flag in SMB2+ TreeConnect if needed
    (fate#323482).

  - cifs: use DFS pathnames in SMB2+ Create requests
    (fate#323482).

  - cpufreq: intel_pstate: Disable energy efficiency
    optimization (bsc#1054654).

  - cxgb4: Fix stack out-of-bounds read due to wrong size to
    t4_record_mbox() (bsc#1021424 bsc#1022743).

  - device-dax: fix cdev leak (bsc#1057047).

  - dmaengine: mv_xor_v2: do not use descriptors not acked
    by async_tx (bsc#1056849).

  - dmaengine: mv_xor_v2: enable XOR engine after its
    configuration (bsc#1056849).

  - dmaengine: mv_xor_v2: fix tx_submit() implementation
    (bsc#1056849).

  - dmaengine: mv_xor_v2: handle mv_xor_v2_prep_sw_desc()
    error properly (bsc#1056849).

  - dmaengine: mv_xor_v2: properly handle wrapping in the
    array of HW descriptors (bsc#1056849).

  - dmaengine: mv_xor_v2: remove interrupt coalescing
    (bsc#1056849).

  - dmaengine: mv_xor_v2: set DMA mask to 40 bits
    (bsc#1056849).

  - drivers: base: cacheinfo: fix boot error message when
    acpi is enabled (bsc#1057849).

  - edac, thunderx: Fix a warning during l2c debugfs node
    creation (bsc#1057038).

  - edac, thunderx: Fix error handling path in
    thunderx_lmc_probe() (bsc#1057038).

  - fs/proc: kcore: use kcore_list type to check for
    vmalloc/module address (bsc#1046529).

  - gfs2: Do not clear SGID when inheriting ACLs
    (bsc#1012829).

  - ib/hns: checking for IS_ERR() instead of NULL
    (bsc#1056849).

  - ibmvnic: Clean up resources on probe failure
    (fate#323285, bsc#1058116).

  - ib/rxe: Add dst_clone() in prepare_ipv6_hdr()
    (bsc#1049361).

  - ib/rxe: Avoid ICRC errors by copying into the skb first
    (bsc#1049361).

  - ib/rxe: Disable completion upcalls when a CQ is
    destroyed (bsc#1049361).

  - ib/rxe: Fix destination cache for IPv6 (bsc#1049361).

  - ib/rxe: Fix up rxe_qp_cleanup() (bsc#1049361).

  - ib/rxe: Fix up the responder's find_resources() function
    (bsc#1049361).

  - ib/rxe: Handle NETDEV_CHANGE events (bsc#1049361).

  - ib/rxe: Move refcounting earlier in rxe_send()
    (bsc#1049361).

  - ib/rxe: Remove dangling prototype (bsc#1049361).

  - ib/rxe: Remove unneeded initialization in prepare6()
    (bsc#1049361).

  - ib/rxe: Set dma_mask and coherent_dma_mask
    (bsc#1049361).

  - iommu/arm-smmu-v3, acpi: Add temporary Cavium SMMU-V3
    IORT model number definitions (bsc#1036060).

  - iommu/arm-smmu-v3: Increase CMDQ drain timeout value
    (bsc#1035479). Refresh patch to mainline version

  - irqchip/gic-v3-its: Fix command buffer allocation
    (bsc#1057067).

  - iwlwifi: mvm: do not send CTDP commands via debugfs if
    not supported (bsc#1031717).

  - kernel/*: switch to memdup_user_nul() (bsc#1048893).

  - lightnvm: remove unused rq parameter of
    nvme_nvm_rqtocmd() to kill warning (FATE#319466).

  - md/raid5: fix a race condition in stripe batch
    (linux-stable).

  - mmc: sdhci-xenon: add set_power callback (bsc#1057035).

  - mmc: sdhci-xenon: Fix the work flow in xenon_remove()
    (bsc#1057035).

  - mm/page_alloc.c: apply gfp_allowed_mask before the first
    allocation attempt (bnc#971975 VM -- git fixes).

  - mm/vmalloc.c: huge-vmap: fail gracefully on unexpected
    huge vmap mappings (bsc#1046529).

  - new helper: memdup_user_nul() (bsc#1048893).

  - nfs: flush data when locking a file to ensure cache
    coherence for mmap (bsc#981309).

  - pci: rockchip: Handle regulator_get_current_limit()
    failure correctly (bsc#1056849).

  - pci: rockchip: Use normal register bank for config
    accessors (bsc#1056849).

  - pm / Domains: Fix unsafe iteration over modified list of
    domains (bsc#1056849).

  - rtnetlink: fix rtnl_vfinfo_size (bsc#1056261).

  - scsi: hisi_sas: add missing break in switch statement
    (bsc#1056849).

  - sysctl: fix lax sysctl_check_table() sanity check
    (bsc#1048893).

  - sysctl: fold sysctl_writes_strict checks into helper
    (bsc#1048893).

  - sysctl: kdoc'ify sysctl_writes_strict (bsc#1048893).

  - sysctl: simplify unsigned int support (bsc#1048893).

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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056849"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057849"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-base-debuginfo-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debuginfo-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-debugsource-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-debug-devel-debuginfo-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-base-debuginfo-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debuginfo-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-debugsource-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-default-devel-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-devel-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-html-4.4.87-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-docs-pdf-4.4.87-25.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-macros-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-build-debugsource-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-obs-qa-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-source-vanilla-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-syms-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-base-debuginfo-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debuginfo-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-debugsource-4.4.87-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"kernel-vanilla-devel-4.4.87-25.1") ) flag++;

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
