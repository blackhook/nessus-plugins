#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0202. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121453);
  script_version("1.8");
  script_cvs_date("Date: 2019/10/24 15:35:46");

  script_cve_id("CVE-2018-18397");
  script_xref(name:"RHSA", value:"2019:0202");

  script_name(english:"RHEL 7 : kernel (RHSA-2019:0202)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 7.5
Extended Update Support.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* kernel: userfaultfd bypasses tmpfs file permissions (CVE-2018-18397)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Bug Fix(es) :

* When applying two instances of the kprobe debugging mechanism to the
same function, one of the kprobes in some cases failed, depending on
the kernel address space layout. Consequently, a kprobe registration
error occurred. This update fixes the bug in the kprobes registration
code to properly detect and handle ftrace-based kprobes. As a result,
both kprobes now apply successfully in the described scenario.
(BZ#1647815)

* Under heavy mad packet load, the SELinux checks in the mad packet
queries for InfiniBand (IB) fabrics significantly increased the mad
packet execution time. Consequently, if a single machine was executing
a large perfquery to the IB switches of a High Performance (HPC)
fabric, mad_rpc timeouts occurred, and the query failed even with
SELinux disabled. This update eliminates the SELinux checks when
SELinux is disabled. As a result, the mad packet queries through
perfquery now have their original run times when SELinux is disabled.
(BZ#1648810)

* Previously, a file-system shutdown process caused by an I/O error
could race against a running fstrim process to acquire a xfs buffer
lock. Consequently, the file-system shutdown process never completed
due to a deadlock and the file-system became unresponsive, unable to
be unmounted. This update fixes the lock ordering so that the deadlock
no longer occurs and the file-system shutdown process now completes in
the described scenario. (BZ#1657142)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-18397"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/30");
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
if (! preg(pattern:"^7\.5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-18397");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2019:0202");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:0202";
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
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", reference:"kernel-abi-whitelists-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debug-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debug-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debug-debuginfo-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debug-devel-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-devel-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-devel-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", reference:"kernel-doc-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-headers-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-headers-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-kdump-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-kdump-debuginfo-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"kernel-kdump-devel-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"perf-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"perf-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"perf-debuginfo-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"python-perf-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"python-perf-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"s390x", reference:"python-perf-debuginfo-3.10.0-862.27.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", sp:"5", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-862.27.1.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
