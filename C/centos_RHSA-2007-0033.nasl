#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0033 and 
# CentOS Errata and Security Advisory 2007:0033 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24877);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0238", "CVE-2007-0239", "CVE-2007-1466");
  script_bugtraq_id(22812, 23006, 23067);
  script_xref(name:"RHSA", value:"2007:0033");

  script_name(english:"CentOS 3 / 4 : openoffice.org (CESA-2007:0033)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages to correct security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenOffice.org is an office productivity suite that includes desktop
applications such as a word processor, spreadsheet, presentation
manager, formula editor, and drawing program.

iDefense reported an integer overflow flaw in libwpd, a library used
internally to OpenOffice.org for handling Word Perfect documents. An
attacker could create a carefully crafted Word Perfect file that could
cause OpenOffice.org to crash or possibly execute arbitrary code if
the file was opened by a victim. (CVE-2007-1466)

John Heasman discovered a stack overflow in the StarCalc parser in
OpenOffice.org. An attacker could create a carefully crafted StarCalc
file that could cause OpenOffice.org to crash or possibly execute
arbitrary code if the file was opened by a victim. (CVE-2007-0238)

Flaws were discovered in the way OpenOffice.org handled hyperlinks. An
attacker could create an OpenOffice.org document which could run
commands if a victim opened the file and clicked on a malicious
hyperlink. (CVE-2007-0239)

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain backported fixes for these issues.

Red Hat would like to thank Fridrich Strba for alerting us to the
issue CVE-2007-1466 and providing a patch, and John Heasman for
CVE-2007-0238."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013628.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0b13f62"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013629.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8fb2311"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013635.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38bb6440"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013636.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad7a5339"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-1.1.2-38.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-1.1.2-38.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-38.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.2-38.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-libs-1.1.2-38.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-libs-1.1.2-38.2.0.EL3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-1.1.5-10.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-1.1.5-10.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-i18n-1.1.5-10.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.5-10.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-kde-1.1.5-10.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-libs-1.1.5-10.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-libs-1.1.5-10.6.0.EL4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org / openoffice.org-i18n / openoffice.org-kde / etc");
}
