#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:066. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12468);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0077");
  script_xref(name:"RHSA", value:"2004:066");

  script_name(english:"RHEL 3 : kernel (RHSA-2004:066)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix a security vulnerability that may
allow local users to gain root privileges are now available. These
packages also resolve other minor issues.

The Linux kernel handles the basic functions of the operating system.

Paul Starzetz discovered a flaw in return value checking in mremap()
in the Linux kernel versions 2.4.24 and previous that may allow a
local attacker to gain root privileges. No exploit is currently
available; however this issue is exploitable. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0077 to this issue.

All users are advised to upgrade to these errata packages, which
contain backported security patches that correct these issues.

Red Hat would like to thank Paul Starzetz from ISEC for reporting this
issue.

For the IBM S/390 and IBM eServer zSeries architectures, the upstream
version of the s390utils package (which fixes a bug in the zipl
bootloader) is also included."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0077"
  );
  # http://www10.software.ibm.com/developerworks/opensource/linux390/
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ibm.com/us-en/?ar=1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2004:066"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:s390utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2004-0077");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2004:066");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:066";
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
  if (rpm_check(release:"RHEL3", reference:"kernel-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-doc-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-hugemem-unsupported-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"kernel-smp-unsupported-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-source-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kernel-unsupported-2.4.21-9.0.1.EL")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"s390", reference:"s390utils-1.2.4-3")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"s390x", reference:"s390utils-1.2.4-3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-doc / kernel-hugemem / etc");
  }
}
