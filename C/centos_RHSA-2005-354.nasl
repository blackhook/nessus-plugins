#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:354 and 
# CentOS Errata and Security Advisory 2005:354 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21809);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-0888", "CVE-2004-1125");
  script_xref(name:"RHSA", value:"2005:354");

  script_name(english:"CentOS 3 : tetex (CESA-2005:354)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tetex packages that fix several integer overflows are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

TeTeX is an implementation of TeX for Linux or UNIX systems. TeX takes
a text file and a set of formatting commands as input and creates a
typesetter-independent .dvi (DeVice Independent) file as output.

A number of security flaws have been found affecting libraries used
internally within teTeX. An attacker who has the ability to trick a
user into processing a malicious file with teTeX could cause teTeX to
crash or possibly execute arbitrary code.

A number of integer overflow bugs that affect Xpdf were discovered.
The teTeX package contains a copy of the Xpdf code used for parsing
PDF files and is therefore affected by these bugs. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2004-0888 and CVE-2004-1125 to these issues.

A number of integer overflow bugs that affect libtiff were discovered.
The teTeX package contains an internal copy of libtiff used for
parsing TIFF image files and is therefore affected by these bugs. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2004-0803, CVE-2004-0804 and CVE-2004-0886 to
these issues.

Also latex2html is added to package tetex-latex for 64bit platforms.

Users of teTeX should upgrade to these updated packages, which contain
backported patches and are not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011520.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5eb701c0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011523.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?766e7d2d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011524.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?315b9f28"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tetex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/01");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"tetex-1.0.7-67.7")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-afm-1.0.7-67.7")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-doc-1.0.7-67.7")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-dvips-1.0.7-67.7")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-fonts-1.0.7-67.7")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-latex-1.0.7-67.7")) flag++;
if (rpm_check(release:"CentOS-3", reference:"tetex-xdvi-1.0.7-67.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-doc / tetex-dvips / tetex-fonts / etc");
}
