#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0206 and 
# CentOS Errata and Security Advisory 2006:0206 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21986);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0301");
  script_xref(name:"RHSA", value:"2006:0206");

  script_name(english:"CentOS 4 : kdegraphics (CESA-2006:0206)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdegraphics packages that resolve a security issue in kpdf are
now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kdegraphics packages contain applications for the K Desktop
Environment including kpdf, a pdf file viewer.

A heap based buffer overflow bug was discovered in kpdf. An attacker
could construct a carefully crafted PDF file that could cause kpdf to
crash or possibly execute arbitrary code when opened. The Common
Vulnerabilities and Exposures project assigned the name CVE-2006-0301
to this issue.

Users of kpdf should upgrade to these updated packages, which contain
a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-February/012641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0360934d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-February/012642.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc8abb68"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-February/012648.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26ddf183"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdegraphics packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"kdegraphics-3.3.1-3.7")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdegraphics-devel-3.3.1-3.7")) flag++;


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
