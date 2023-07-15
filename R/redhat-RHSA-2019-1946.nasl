#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1946. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(127633);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2017-12154",
    "CVE-2017-15129",
    "CVE-2017-15274",
    "CVE-2018-3693",
    "CVE-2018-14633"
  );
  script_xref(name:"RHSA", value:"2019:1946");

  script_name(english:"RHEL 7 : kernel (RHSA-2019:1946)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.4
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* An industry-wide issue was found in the way many modern
microprocessor designs have implemented speculative execution of
instructions past bounds check. The flaw relies on the presence of a
precisely-defined instruction sequence in the privileged code and the
fact that memory writes occur to an address which depends on the
untrusted value. Such writes cause an update into the microprocessor's
data cache even for speculatively executed instructions that never
actually commit (retire). As a result, an unprivileged attacker could
use this flaw to influence speculative execution and/or read
privileged memory by conducting targeted cache side-channel attacks.
(CVE-2018-3693)

* Kernel: kvm: nVMX: L2 guest could access hardware(L0) CR8 register
(CVE-2017-12154)

* kernel: net: double-free and memory corruption in get_net_ns_by_id()
(CVE-2017-15129)

* kernel: dereferencing NULL payload with nonzero length
(CVE-2017-15274)

* kernel: stack-based buffer overflow in chap_server_compute_md5() in
iscsi target (CVE-2018-14633)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* ovl_create can return positive retval and crash the host
(BZ#1696290)

* THP: Race between MADV_DONTNEED and NUMA hinting node migration code
(BZ# 1698105)

* RHEL7.6 - Kernel changes for count cache flush Spectre v2 mitigation
(BZ# 1708543)

* Poor system performance from thundering herd of kworkers competing
for mddev->flush_bio ownership (BZ#1712762)

* [RHEL7.7] RAID1 `write-behind` causes a kernel panic (BZ#1712999)

Enhancement(s) :

* [Intel 7.5 FEAT] i40evf - Update to latest upstream driver version
(BZ# 1722774)

* [netdrv] i40e/i40evf: Fix use after free in Rx cleanup path [7.4.z]
(BZ# 1723831)

Users of kernel are advised to upgrade to these updated packages,
which fix these bugs and add these enhancements.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/solutions/3523601");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:1946");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-12154");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-15129");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-15274");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-3693");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14633");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14633");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-12154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7\.4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.4", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-12154", "CVE-2017-15129", "CVE-2017-15274", "CVE-2018-14633", "CVE-2018-3693");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:1946");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:1946";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", reference:"kernel-abi-whitelists-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debug-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debug-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-devel-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-devel-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", reference:"kernel-doc-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-headers-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-headers-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-kdump-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-tools-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"perf-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"perf-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"perf-debuginfo-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"python-perf-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"python-perf-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-693.55.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"4", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-693.55.1.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
