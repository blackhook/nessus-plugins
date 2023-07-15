#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:598 and 
# CentOS Errata and Security Advisory 2005:598 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21951);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2104");
  script_xref(name:"RHSA", value:"2005:598");

  script_name(english:"CentOS 3 / 4 : sysreport (CESA-2005:598)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sysreport package that fixes an insecure temporary file
flaw is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Sysreport is a utility that gathers information about a system's
hardware and configuration. The information can then be used for
diagnostic purposes and debugging.

Bill Stearns discovered a bug in the way sysreport creates temporary
files. It is possible that a local attacker could obtain sensitive
information about the system when sysreport is run. The Common
Vulnerabilities and Exposures project assigned the name CVE-2005-2104
to this issue.

Users of sysreport should update to this erratum package, which
contains a patch that resolves this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012020.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f033cfc3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d6bc2d3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17cd3811"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012045.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7594db3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-August/012046.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00a9a6a2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sysreport package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sysreport");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/10");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"sysreport-1.3.7.2-9")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"sysreport-1.3.7.2-9")) flag++;

if (rpm_check(release:"CentOS-4", reference:"sysreport-1.3.15-5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sysreport");
}
