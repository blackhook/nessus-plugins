#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0720 and 
# CentOS Errata and Security Advisory 2007:0720 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25812);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-3387");
  script_bugtraq_id(25124);
  script_xref(name:"RHSA", value:"2007:0720");

  script_name(english:"CentOS 3 / 4 / 5 : cups (CESA-2007:0720)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated CUPS packages that fix a security issue in PDF handling are
now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

Maurycy Prodeus discovered an integer overflow flaw in the way CUPS
processes PDF files. An attacker could create a malicious PDF file
that could potentially execute arbitrary code when printed.
(CVE-2007-3387)

All users of CUPS should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a74acd85"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?651a5956"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014085.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f032f97a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a36c6d1d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014089.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2b94ccb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014093.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc534c0c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014104.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2bdac9ed"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-July/014105.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50378ba1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/31");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"cups-1.1.17-13.3.45")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-devel-1.1.17-13.3.45")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-libs-1.1.17-13.3.45")) flag++;

if (rpm_check(release:"CentOS-4", reference:"cups-1.1.22-0.rc1.9.20.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cups-devel-1.1.22-0.rc1.9.20.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cups-libs-1.1.22-0.rc1.9.20.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"cups-1.2.4-11.5.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.2.4-11.5.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.2.4-11.5.3.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.2.4-11.5.3.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs / cups-lpd");
}
