#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0235 and 
# CentOS Errata and Security Advisory 2008:0235 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32000);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1686");
  script_bugtraq_id(28665);
  script_xref(name:"RHSA", value:"2008:0235");

  script_name(english:"CentOS 4 / 5 : speex (CESA-2008:0235)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated speex packages that fix a security issue are now available for
Red Hat Enterprise Linux 4 and Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Speex is a patent-free compression format designed especially for
speech. The Speex package contains a library for handling Speex files
and sample encoder and decoder implementations using this library.

The Speex library was found to not properly validate input values read
from the Speex files headers. An attacker could create a malicious
Speex file that would crash an application or, possibly, allow
arbitrary code execution with the privileges of the application
calling the Speex library. (CVE-2008-1686)

All users of speex are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b22ca94f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014843.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc4cc560"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97b7746e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014853.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?585402b5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-April/014861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3af1768"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected speex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:speex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:speex-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/22");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"speex-1.0.4-4.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"speex-1.0.4-4.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"speex-1.0.4-4.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"speex-devel-1.0.4-4.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"speex-devel-1.0.4-4.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"speex-devel-1.0.4-4.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"speex-1.0.5-4.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"speex-devel-1.0.5-4.el5_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "speex / speex-devel");
}
