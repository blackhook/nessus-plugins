#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0573. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21916);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
  script_xref(name:"RHSA", value:"2006:0573");

  script_name(english:"RHEL 3 / 4 : openoffice.org (RHSA-2006:0573)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenOffice.org is an office productivity suite that includes desktop
applications such as a word processor, spreadsheet, presentation
manager, formula editor, and drawing program.

A Sun security specialist reported an issue with the application
framework. An attacker could put macros into document locations that
could cause OpenOffice.org to execute them when the file was opened by
a victim. (CVE-2006-2198)

A bug was found in the OpenOffice.org Java virtual machine
implementation. An attacker could write a carefully crafted Java
applet that can break through the 'sandbox' and have full access to
system resources with the current user privileges. (CVE-2006-2199)

A buffer overflow bug was found in the OpenOffice.org file processor.
An attacker could create a carefully crafted XML file that could cause
OpenOffice.org to write data to an arbitrary location in memory when
the file was opened by a victim. (CVE-2006-3117)

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain backported fixes for these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-2199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-3117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/bulletin-20060629.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2006:0573"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0573";
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
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openoffice.org-1.1.2-34.2.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-34.2.0.EL3")) flag++;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openoffice.org-libs-1.1.2-34.2.0.EL3")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-1.1.2-34.6.0.EL4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-34.6.0.EL4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-kde-1.1.2-34.6.0.EL4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-libs-1.1.2-34.6.0.EL4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org / openoffice.org-i18n / openoffice.org-kde / etc");
  }
}
