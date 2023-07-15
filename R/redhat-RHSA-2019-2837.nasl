#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2837. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129149);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2019-11810", "CVE-2019-5489");
  script_xref(name:"RHSA", value:"2019:2837");

  script_name(english:"RHEL 7 : kernel (RHSA-2019:2837)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.6
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* Kernel: page cache side channel attacks (CVE-2019-5489)

* kernel: a NULL pointer dereference in drivers/scsi/megaraid/
megaraid_sas_base.c leading to DoS (CVE-2019-11810)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* [RHEL7.7] Refined TSC clocksource calibration occasionally fails on
some SkyLake-X servers (BZ#1719781)

* tc: incorrect flows statistic on bond device (shared block)
(BZ#1719786)

* Qlogic qla2xxx driver version 10.x.x.x pins all irq requests to cpu0
and associated cores (BZ#1720956)

* libceph: handle an empty authorize reply (BZ#1722769)

* RHEL7.6 - pkey: Indicate old mkvp only if old and curr. mkvp are
different (BZ#1723153)

* RHEL7.6 - qdio: clear intparm during shutdown (BZ#1723154)

* [RHEL7] Fix Spectre V1 vulnerability in vhost code (BZ#1724079)

* [Stratus] 802.3ad bond group member disabled after reboot (or I/O
failure testing) (BZ#1725037)

* Accept validate negotiate if server returns NT_STATUS_NOT_SUPPORTED.
(BZ# 1726563)

* [Regression] RHEL7.6 - losing dirty bit during THP splitting,
possible memory corruption (mm-) (BZ#1727108)

* [Intel 7.7 BUG] BUG: unable to handle kernel paging request at
000000006b4fd010 (BZ#1727110)

* KVM tracebacks causing significant latency to VM (BZ#1728174)

* NULL pointer dereference in vxlan_dellink+0xaa (BZ#1728198)

* [rhel7]NULL pointer dereference at vxlan_fill_metadata_dst
(BZ#1728199)

* After update to RHEL 7.6 (3.10.0-957.1.3.el7.x86_64) from 7.4,
customer has experienced multiple panics in kernel at BUG at
drivers/iommu/iova.c:859! (BZ#1731300)

* kernel build: speed up debuginfo extraction (BZ#1731464)

* hpsa driver hard lockup trying to complete a no longer valid
completion on the stack (BZ#1731980)

* XFS: forced shutdown in xfs_trans_cancel during create near ENOSPC
(BZ# 1731982)

* TCP packets are segmented when sent to the VLAN device when coming
from VXLAN dev. (BZ#1732812)

* panic handing smb2_reconnect due to a use after free (BZ#1737381)

* Backport TCP follow-up for small buffers (BZ#1739129)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-11810"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5489");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7\.6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.6", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-11810", "CVE-2019-5489");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:2837");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:2837";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"bpftool-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", reference:"kernel-abi-whitelists-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-debug-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-debug-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-devel-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-devel-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", reference:"kernel-doc-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-headers-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-headers-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-kdump-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-tools-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"perf-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"perf-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"perf-debuginfo-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"python-perf-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"python-perf-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-957.35.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"6", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-957.35.1.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
