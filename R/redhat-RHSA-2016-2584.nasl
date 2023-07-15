#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2584. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94547);
  script_version("2.12");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2013-4312", "CVE-2015-8374", "CVE-2015-8543", "CVE-2015-8746", "CVE-2015-8812", "CVE-2015-8844", "CVE-2015-8845", "CVE-2015-8956", "CVE-2016-2053", "CVE-2016-2069", "CVE-2016-2117", "CVE-2016-2384", "CVE-2016-2847", "CVE-2016-3070", "CVE-2016-3156", "CVE-2016-3699", "CVE-2016-3841", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4581", "CVE-2016-4794", "CVE-2016-5829", "CVE-2016-6136", "CVE-2016-6198", "CVE-2016-6327", "CVE-2016-6480", "CVE-2017-13167");
  script_xref(name:"RHSA", value:"2016:2584");

  script_name(english:"RHEL 7 : kernel-rt (RHSA-2016:2584)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel-rt is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel-rt packages provide the Real Time Linux Kernel, which
enables fine-tuning for systems with extremely high determinism
requirements.

Security Fix(es) :

* It was found that the Linux kernel's IPv6 implementation mishandled
socket options. A local attacker could abuse concurrent access to the
socket options to escalate their privileges, or cause a denial of
service (use-after-free and system crash) via a crafted sendmsg system
call. (CVE-2016-3841, Important)

* Several Moderate and Low impact security issues were found in the
Linux kernel. Space precludes documenting each of these issues in this
advisory. Refer to the CVE links in the References section for a
description of each of these vulnerabilities. (CVE-2013-4312,
CVE-2015-8374, CVE-2015-8543, CVE-2015-8812, CVE-2015-8844,
CVE-2015-8845, CVE-2016-2053, CVE-2016-2069, CVE-2016-2847,
CVE-2016-3156, CVE-2016-4581, CVE-2016-4794, CVE-2016-5829,
CVE-2016-6136, CVE-2016-6198, CVE-2016-6327, CVE-2016-6480,
CVE-2015-8746, CVE-2015-8956, CVE-2016-2117, CVE-2016-2384,
CVE-2016-3070, CVE-2016-3699, CVE-2016-4569, CVE-2016-4578)

Red Hat would like to thank Philip Pettersson (Samsung) for reporting
CVE-2016-2053; Tetsuo Handa for reporting CVE-2016-2847; the Virtuozzo
kernel team and Solar Designer (Openwall) for reporting CVE-2016-3156;
Justin Yackoski (Cryptonite) for reporting CVE-2016-2117; and Linn
Crosetto (HP) for reporting CVE-2016-3699. The CVE-2015-8812 issue was
discovered by Venkatesh Pottem (Red Hat Engineering); the
CVE-2015-8844 and CVE-2015-8845 issues were discovered by Miroslav
Vadkerti (Red Hat Engineering); the CVE-2016-4581 issue was discovered
by Eric W. Biederman (Red Hat); the CVE-2016-6198 issue was discovered
by CAI Qian (Red Hat); and the CVE-2016-3070 issue was discovered by
Jan Stancek (Red Hat).

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-4312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-8956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-13167"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2013-4312", "CVE-2015-8374", "CVE-2015-8543", "CVE-2015-8746", "CVE-2015-8812", "CVE-2015-8844", "CVE-2015-8845", "CVE-2015-8956", "CVE-2016-2053", "CVE-2016-2069", "CVE-2016-2117", "CVE-2016-2384", "CVE-2016-2847", "CVE-2016-3070", "CVE-2016-3156", "CVE-2016-3699", "CVE-2016-3841", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4581", "CVE-2016-4794", "CVE-2016-5829", "CVE-2016-6136", "CVE-2016-6198", "CVE-2016-6327", "CVE-2016-6480", "CVE-2017-13167");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2016:2584");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:2584";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-debuginfo-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-devel-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-kvm-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debug-kvm-debuginfo-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debuginfo-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-debuginfo-common-x86_64-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-devel-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-rt-doc-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-kvm-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-kvm-debuginfo-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-debuginfo-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-devel-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-kvm-3.10.0-514.rt56.420.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kernel-rt-trace-kvm-debuginfo-3.10.0-514.rt56.420.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt / kernel-rt-debug / kernel-rt-debug-debuginfo / etc");
  }
}
