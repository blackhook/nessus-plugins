#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1502 and 
# CentOS Errata and Security Advisory 2009:1502 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43802);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0791", "CVE-2009-1188", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
  script_xref(name:"RHSA", value:"2009:1502");

  script_name(english:"CentOS 5 : kdegraphics (CESA-2009:1502)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdegraphics packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kdegraphics packages contain applications for the K Desktop
Environment, including KPDF, a viewer for Portable Document Format
(PDF) files.

Multiple integer overflow flaws were found in KPDF. An attacker could
create a malicious PDF file that would cause KPDF to crash or,
potentially, execute arbitrary code when opened. (CVE-2009-0791,
CVE-2009-1188, CVE-2009-3604, CVE-2009-3606, CVE-2009-3608,
CVE-2009-3609)

Red Hat would like to thank Adam Zabrocki for reporting the
CVE-2009-3604 issue, and Chris Rohlf for reporting the CVE-2009-3608
issue.

Users are advised to upgrade to these updated packages, which contain
a backported patch to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016232.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c5ad819"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-October/016233.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ee458b8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdegraphics packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"kdegraphics-3.5.4-15.el5_4.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdegraphics-devel-3.5.4-15.el5_4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdegraphics / kdegraphics-devel");
}
