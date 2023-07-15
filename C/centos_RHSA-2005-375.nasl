#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:375 and 
# CentOS Errata and Security Advisory 2005:375 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21813);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0941");
  script_xref(name:"RHSA", value:"2005:375");

  script_name(english:"CentOS 3 / 4 : OpenOffice.org (CESA-2005:375)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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

A heap based buffer overflow bug was found in the OpenOffice.org DOC
file processor. An attacker could create a carefully crafted DOC file
in such a way that it could cause OpenOffice.org to execute arbitrary
code when the file was opened by a victim. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-0941 to this issue.

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain backported fixes for these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011608.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c8ddcc4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011611.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77d82674"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011612.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e99c74c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-1.1.2-24.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-1.1.2-24.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-24.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.2-24.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-libs-1.1.2-24.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-libs-1.1.2-24.2.0.EL3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-1.1.2-24.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-1.1.2-24.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-24.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.2-24.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-kde-1.1.2-24.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-kde-1.1.2-24.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-libs-1.1.2-24.6.0.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-libs-1.1.2-24.6.0.EL4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
