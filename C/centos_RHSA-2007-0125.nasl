#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0125 and 
# CentOS Errata and Security Advisory 2007:0125 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24920);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1003", "CVE-2007-1351", "CVE-2007-1352", "CVE-2007-1667");
  script_bugtraq_id(23283, 23284, 23300);
  script_xref(name:"RHSA", value:"2007:0125");

  script_name(english:"CentOS 3 : XFree86 (CESA-2007:0125)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated XFree86 packages that fix a number of security issues are now
available for Red Hat Enterprise Linux 2.1 and 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

XFree86 is an implementation of the X Window System, which provides
the core functionality for the Linux graphical desktop.

iDefense reported an integer overflow flaw in the XFree86 XC-MISC
extension. A malicious authorized client could exploit this issue to
cause a denial of service (crash) or potentially execute arbitrary
code with root privileges on the XFree86 server. (CVE-2007-1003)

iDefense reported two integer overflows in the way X.org handled
various font files. A malicious local user could exploit these issues
to potentially execute arbitrary code with the privileges of the X.org
server. (CVE-2007-1351, CVE-2007-1352)

An integer overflow flaw was found in the XFree86 XGetPixel()
function. Improper use of this function could cause an application
calling it to function improperly, possibly leading to a crash or
arbitrary code execution. (CVE-2007-1667)

Users of XFree86 should upgrade to these updated packages, which
contain a backported patch and is not vulnerable to this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013640.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa2d67ec"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e8a3c47"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-April/013643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6c4813e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xfree86 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-14-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-14-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-15-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-15-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-2-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-2-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-9-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-ISO8859-9-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-base-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-libs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-syriac-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-truetype-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:XFree86-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/05");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"XFree86-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-100dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-75dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-14-100dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-14-75dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-15-100dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-15-75dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-2-100dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-2-75dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-9-100dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-ISO8859-9-75dpi-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Mesa-libGL-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Mesa-libGLU-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Xnest-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-Xvfb-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-base-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-cyrillic-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-devel-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-doc-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-font-utils-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-libs-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-libs-data-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-sdk-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-syriac-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-tools-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-truetype-fonts-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-twm-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-xauth-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-xdm-4.3.0-120.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"XFree86-xfs-4.3.0-120.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "XFree86 / XFree86-100dpi-fonts / XFree86-75dpi-fonts / etc");
}
