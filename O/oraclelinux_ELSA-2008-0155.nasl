#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0155 and 
# Oracle Linux Security Advisory ELSA-2008-0155 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67660);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-0411");
  script_bugtraq_id(28017);
  script_xref(name:"RHSA", value:"2008:0155");

  script_name(english:"Oracle Linux 3 / 4 / 5 : ghostscript (ELSA-2008-0155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0155 :

Updated ghostscript packages that fix a security issue are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Ghostscript is a program for displaying PostScript files, or printing
them to non-PostScript printers.

Chris Evans from the Google Security Team reported a stack-based
buffer overflow flaw in Ghostscript's zseticcspace() function. An
attacker could create a malicious PostScript file that would cause
Ghostscript to execute arbitrary code when opened. (CVE-2008-0411)

These updated packages also fix a bug, which prevented the pxlmono
printer driver from producing valid output on Red Hat Enterprise Linux
4.

All users of ghostscript are advised to upgrade to these updated
packages, which contain a backported patch to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-February/000525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-February/000526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-February/000528.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hpijs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"ghostscript-7.05-32.1.13")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"ghostscript-7.05-32.1.13")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"ghostscript-devel-7.05-32.1.13")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"ghostscript-devel-7.05-32.1.13")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"hpijs-1.3-32.1.13")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"hpijs-1.3-32.1.13")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"ghostscript-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ghostscript-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ghostscript-devel-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ghostscript-devel-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ghostscript-gtk-7.07-33.2.el4_6.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ghostscript-gtk-7.07-33.2.el4_6.1")) flag++;

if (rpm_check(release:"EL5", reference:"ghostscript-8.15.2-9.1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"ghostscript-devel-8.15.2-9.1.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"ghostscript-gtk-8.15.2-9.1.el5_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-devel / ghostscript-gtk / hpijs");
}
