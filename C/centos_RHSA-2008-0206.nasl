#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0206 and 
# CentOS Errata and Security Advisory 2008:0206 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31741);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0888", "CVE-2005-0206", "CVE-2008-0053", "CVE-2008-1373", "CVE-2008-1374");
  script_bugtraq_id(28307, 28334, 28544);
  script_xref(name:"RHSA", value:"2008:0206");

  script_name(english:"CentOS 3 / 4 : cups (CESA-2008:0206)");
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

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

Two overflows were discovered in the HP-GL/2-to-PostScript filter. An
attacker could create a malicious HP-GL/2 file that could possibly
execute arbitrary code as the 'lp' user if the file is printed.
(CVE-2008-0053)

A buffer overflow flaw was discovered in the GIF decoding routines
used by CUPS image converting filters 'imagetops' and 'imagetoraster'.
An attacker could create a malicious GIF file that could possibly
execute arbitrary code as the 'lp' user if the file was printed.
(CVE-2008-1373)

It was discovered that the patch used to address CVE-2004-0888 in CUPS
packages in Red Hat Enterprise Linux 3 and 4 did not completely
resolve the integer overflow in the 'pdftops' filter on 64-bit
platforms. An attacker could create a malicious PDF file that could
possibly execute arbitrary code as the 'lp' user if the file was
printed. (CVE-2008-1374)

All cups users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014795.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccee7d61"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014796.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?beddc91a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014799.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38c8fe7a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11df26ef"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014803.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf1b29b8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014804.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b08a3a94"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"cups-1.1.17-13.3.52")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-devel-1.1.17-13.3.52")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-libs-1.1.17-13.3.52")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-1.1.22-0.rc1.9.20.2.el4_6.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-1.1.22-0.rc1.9.20.2.c4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-1.1.22-0.rc1.9.20.2.el4_6.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_6.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-devel-1.1.22-0.rc1.9.20.2.c4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_6.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_6.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-libs-1.1.22-0.rc1.9.20.2.c4.6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_6.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs");
}
