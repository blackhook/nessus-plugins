#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1682.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141514);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/12");

  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-25212", "CVE-2020-25645");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2020-1682)");
  script_summary(english:"Check for the openSUSE-2020-1682 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The openSUSE Leap 15.1 kernel was updated to receive various security
and bugfixes.

The following security bugs were fixed :

  - CVE-2020-12351: A type confusion while processing AMP
    packets could be used by physical close attackers to
    crash the kernel or potentially execute code was fixed
    (bsc#1177724).

  - CVE-2020-12352: A stack information leak when handling
    certain AMP packets could be used by physical close
    attackers to leak information from the kernel was fixed
    (bsc#1177725).

  - CVE-2020-25212: A TOCTOU mismatch in the NFS client code
    could be used by local attackers to corrupt memory or
    possibly have unspecified other impact because a size
    check is in fs/nfs/nfs4proc.c instead of
    fs/nfs/nfs4xdr.c, aka CID-b4487b935452 (bnc#1176381).

  - CVE-2020-25645: Traffic between two Geneve endpoints may
    be unencrypted when IPsec is configured to encrypt
    traffic for the specific UDP port used by the GENEVE
    tunnel allowing anyone between the two endpoints to read
    the traffic unencrypted. The main threat from this
    vulnerability is to data confidentiality (bnc#1177511).

The following non-security bugs were fixed :

  - 59c7c3caaaf8 ('nvme: fix possible hang when ns scanning
    fails during error recovery')

  - NFS: On fatal writeback errors, we need to call
    nfs_inode_remove_request() (bsc#1177340).

  - NFS: Revalidate the file mapping on all fatal writeback
    errors (bsc#1177340).

  - drm/sun4i: mixer: Extend regmap max_register
    (git-fixes).

  - ea43d9709f72 ('nvme: fix identify error status silent
    ignore')

  - i2c: meson: fix clock setting overwrite (git-fixes).

  - iommu/vt-d: Correctly calculate agaw in domain_init()
    (bsc#1176400).

  - mac80211: do not allow bigger VHT MPDUs than the
    hardware supports (git-fixes).

  - macsec: avoid use-after-free in macsec_handle_frame()
    (git-fixes).

  - mm: memcg: switch to css_tryget() in
    get_mem_cgroup_from_mm() (bsc#1177685).

  - mmc: core: do not set limits.discard_granularity as 0
    (git-fixes).

  - nvme-multipath: do not reset on unknown status
    (bsc#1174748).

  - nvme-rdma: Avoid double freeing of async event data
    (bsc#1174748).

  - nvme: Fix ctrl use-after-free during sysfs deletion
    (bsc#1174748).

  - nvme: Namepace identification descriptor list is
    optional (bsc#1174748).

  - nvme: add a Identify Namespace Identification Descriptor
    list quirk (bsc#1174748).

  - nvme: fix deadlock caused by ANA update wrong locking
    (bsc#1174748).

  - nvme: fix possible io failures when removing multipathed
    ns (bsc#1174748).

  - nvme: make nvme_identify_ns propagate errors back
    (bsc#1174748).

  - nvme: make nvme_report_ns_ids propagate error back
    (bsc#1174748).

  - nvme: pass status to nvme_error_status (bsc#1174748).

  - nvme: return error from nvme_alloc_ns() (bsc#1174748).

  - powerpc/dma: Fix dma_map_ops::get_required_mask
    (bsc#1065729).

  - scsi: hisi_sas: Add debugfs ITCT file and add file
    operations (bsc#1140683).

  - scsi: hisi_sas: Add manual trigger for debugfs dump
    (bsc#1140683).

  - scsi: hisi_sas: Add missing seq_printf() call in
    hisi_sas_show_row_32() (bsc#1140683).

  - scsi: hisi_sas: Change return variable type in
    phy_up_v3_hw() (bsc#1140683).

  - scsi: hisi_sas: Correct memory allocation size for DQ
    debugfs (bsc#1140683).

  - scsi: hisi_sas: Do some more tidy-up (bsc#1140683).

  - scsi: hisi_sas: Fix a timeout race of driver internal
    and SMP IO (bsc#1140683).

  - scsi: hisi_sas: Fix type casting and missing static
    qualifier in debugfs code (bsc#1140683). Refresh :

  - scsi: hisi_sas: No need to check return value of
    debugfs_create functions (bsc#1140683). Update :

  - scsi: hisi_sas: Some misc tidy-up (bsc#1140683).

  - scsi: qla2xxx: Add IOCB resource tracking (bsc#1176946
    bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Add SLER and PI control support
    (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Add rport fields in debugfs (bsc#1176946
    bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Allow dev_loss_tmo setting for FC-NVMe
    devices (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Correct the check for sscanf() return
    value (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix I/O errors during LIP reset tests
    (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix I/O failures during remote port
    toggle testing (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix MPI reset needed message (bsc#1176946
    bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix buffer-buffer credit extraction error
    (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix crash on session cleanup with unload
    (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix inconsistent format argument type in
    qla_dbg.c (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix inconsistent format argument type in
    tcm_qla2xxx.c (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix inconsistent format argument type in
    qla_os.c (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix memory size truncation (bsc#1176946
    bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix point-to-point (N2N) device discovery
    issue (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Fix reset of MPI firmware (bsc#1176946
    bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Honor status qualifier in FCP_RSP per
    spec (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Make tgt_port_database available in
    initiator mode (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Performance tweak (bsc#1176946
    bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Reduce duplicate code in reporting speed
    (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Remove unneeded variable 'rval'
    (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Setup debugfs entries for remote ports
    (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Update version to 10.02.00.102-k
    (bsc#1176946 bsc#1175520 bsc#1172538).

  - scsi: qla2xxx: Update version to 10.02.00.103-k
    (bsc#1176946 bsc#1175520 bsc#1172538)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177725"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12351");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-base-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-debugsource-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-debug-devel-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-base-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-debugsource-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-default-devel-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-devel-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-docs-html-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-base-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-debugsource-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-kvmsmall-devel-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-macros-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-build-debugsource-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-obs-qa-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-source-vanilla-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-syms-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-base-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debuginfo-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-debugsource-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-4.12.14-lp151.28.75.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-vanilla-devel-debuginfo-4.12.14-lp151.28.75.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
