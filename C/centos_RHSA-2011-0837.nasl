#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0837 and 
# CentOS Errata and Security Advisory 2011:0837 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54936);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1570", "CVE-2010-4541", "CVE-2010-4543", "CVE-2011-1178");
  script_bugtraq_id(37006, 45647);
  script_xref(name:"RHSA", value:"2011:0837");

  script_name(english:"CentOS 4 : gimp (CESA-2011:0837)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gimp packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the GIMP's Microsoft Windows Bitmap (BMP) and Personal
Computer eXchange (PCX) image file plug-ins. An attacker could create
a specially crafted BMP or PCX image file that, when opened, could
cause the relevant plug-in to crash or, potentially, execute arbitrary
code with the privileges of the user running the GIMP. (CVE-2009-1570,
CVE-2011-1178)

A heap-based buffer overflow flaw was found in the GIMP's Paint Shop
Pro (PSP) image file plug-in. An attacker could create a specially
crafted PSP image file that, when opened, could cause the PSP plug-in
to crash or, potentially, execute arbitrary code with the privileges
of the user running the GIMP. (CVE-2010-4543)

A stack-based buffer overflow flaw was found in the GIMP's Sphere
Designer image filter. An attacker could create a specially crafted
Sphere Designer filter configuration file that, when opened, could
cause the Sphere Designer plug-in to crash or, potentially, execute
arbitrary code with the privileges of the user running the GIMP.
(CVE-2010-4541)

Red Hat would like to thank Stefan Cornelius of Secunia Research for
responsibly reporting the CVE-2009-1570 flaw.

Users of the GIMP are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The GIMP
must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-June/017603.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e79990a6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-June/017604.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3613c703"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gimp-2.0.5-7.0.7.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gimp-2.0.5-7.0.7.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gimp-devel-2.0.5-7.0.7.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gimp-devel-2.0.5-7.0.7.el4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-devel");
}
