#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1814. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93364);
  script_version("2.11");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2016-4565", "CVE-2016-5696");
  script_xref(name:"RHSA", value:"2016:1814");

  script_name(english:"RHEL 6 : kernel (RHSA-2016:1814)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.5
Advanced Update Support.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A flaw was found in the way certain interfaces of the Linux kernel's
Infiniband subsystem used write() as bi-directional ioctl()
replacement, which could lead to insufficient memory security checks
when being invoked using the splice() system call. A local
unprivileged user on a system with either Infiniband hardware present
or RDMA Userspace Connection Manager Access module explicitly loaded,
could use this flaw to escalate their privileges on the system.
(CVE-2016-4565, Important)

* It was found that the RFC 5961 challenge ACK rate limiting as
implemented in the Linux kernel's networking subsystem allowed an
off-path attacker to leak certain information about a given connection
by creating congestion on the global challenge ACK rate limit counter
and then measuring the changes by probing packets. An off-path
attacker could use this flaw to either terminate TCP connection and/or
inject payload into non-secured TCP connection between two endpoints
on the network. (CVE-2016-5696, Important)

Red Hat would like to thank Jann Horn for reporting CVE-2016-4565 and
Yue Cao (Cyber Security Group of the CS department of University of
California in Riverside) for reporting CVE-2016-5696.

Bug Fix(es) :

* After upgrading the kernel, CPU load average increased compared to
the prior kernel version due to the modification of the scheduler. The
provided patchset makes the calculation algorithm of this load average
roll back to the status of the previous system version thus resulting
in relatively lower values in the same system load. (BZ#1343010)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5696"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6\.5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2016-4565", "CVE-2016-5696");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2016:1814");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1814";
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
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-abi-whitelists-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-devel-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-doc-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"kernel-firmware-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"kernel-headers-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"perf-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"python-perf-2.6.32-431.73.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-431.73.2.el6")) flag++;

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