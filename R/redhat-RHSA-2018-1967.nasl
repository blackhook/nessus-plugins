#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1967. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110709);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715", "CVE-2018-3639");
  script_xref(name:"RHSA", value:"2018:1967");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"RHEL 7 : kernel-alt (RHSA-2018:1967) (Spectre)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for kernel-alt is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel-alt packages provide the Linux kernel version 4.x.

Security Fix(es) :

* An industry-wide issue was found in the way many modern
microprocessor designs have implemented speculative execution of Load
& Store instructions (a commonly used performance optimization). It
relies on the presence of a precisely-defined instruction sequence in
the privileged code as well as the fact that memory read from address
to which a recent memory write has occurred may see an older value and
subsequently cause an update into the microprocessor's data cache even
for speculatively executed instructions that never actually commit
(retire). As a result, an unprivileged attacker could use this flaw to
read privileged memory by conducting targeted cache side-channel
attacks. (CVE-2018-3639, PowerPC)

* This release also includes next iteration of the CVE-2017-5715
mitigation that includes the SMCCC (Secure Monitor Call Calling
Convention) 1.1 support. (CVE-2017-5715, ARM)

Red Hat would like to thank Google Project Zero for reporting
CVE-2017-5715 and Ken Johnson (Microsoft Security Response Center) and
Jann Horn (Google Project Zero) for reporting CVE-2018-3639.

Bug Fix(es) :

These updated kernel-alt packages include numerous bug fixes. Space
precludes documenting all of the bug fixes in this advisory. See the
descriptions in the related Knowledge Article:
https://access.redhat.com/articles/3485851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-3639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-5715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/3485851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1967"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  cve_list = make_list("CVE-2017-5715", "CVE-2018-3639");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2018:1967");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:1967";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-abi-whitelists-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-debuginfo-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debug-devel-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debuginfo-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-devel-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", reference:"kernel-doc-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-headers-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-debuginfo-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"kernel-kdump-devel-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"perf-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"perf-debuginfo-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-perf-4.14.0-49.8.1.el7a")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-perf-debuginfo-4.14.0-49.8.1.el7a")) flag++;

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
