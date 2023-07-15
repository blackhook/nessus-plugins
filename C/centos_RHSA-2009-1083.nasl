#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1083 and 
# CentOS Errata and Security Advisory 2009:1083 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39303);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0791", "CVE-2009-0949", "CVE-2009-1196");
  script_bugtraq_id(35169);
  script_xref(name:"RHSA", value:"2009:1083");

  script_name(english:"CentOS 3 / 4 : cups (CESA-2009:1083)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX(r) Printing System (CUPS) provides a portable printing
layer for UNIX operating systems. The Internet Printing Protocol (IPP)
allows users to print and manage printing-related tasks over a
network. The CUPS 'pdftops' filter converts Portable Document Format
(PDF) files to PostScript. 'pdftops' is based on Xpdf and the CUPS
imaging library.

A NULL pointer dereference flaw was found in the CUPS IPP routine,
used for processing incoming IPP requests for the CUPS scheduler. An
attacker could use this flaw to send specially crafted IPP requests
that would crash the cupsd daemon. (CVE-2009-0949)

A use-after-free flaw was found in the CUPS scheduler directory
services routine, used to process data about available printers and
printer classes. An attacker could use this flaw to cause a denial of
service (cupsd daemon stop or crash). (CVE-2009-1196)

Multiple integer overflows flaws, leading to heap-based buffer
overflows, were found in the CUPS 'pdftops' filter. An attacker could
create a malicious PDF file that would cause 'pdftops' to crash or,
potentially, execute arbitrary code as the 'lp' user if the file was
printed. (CVE-2009-0791)

Red Hat would like to thank Anibal Sacco from Core Security
Technologies for reporting the CVE-2009-0949 flaw, and Swen van
Brussel for reporting the CVE-2009-1196 flaw.

Users of cups are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, the cupsd daemon will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015957.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3899c64"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?423f1b34"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015959.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b1ea8b4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-June/015960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ea3527d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"cups-1.1.17-13.3.62")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-devel-1.1.17-13.3.62")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-libs-1.1.17-13.3.62")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-1.1.22-0.rc1.9.32.c4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-devel-1.1.22-0.rc1.9.32.c4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-libs-1.1.22-0.rc1.9.32.c4.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs");
}
