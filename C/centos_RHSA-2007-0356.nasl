#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0356 and 
# CentOS Errata and Security Advisory 2007:0356 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25256);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-5793", "CVE-2007-2445");
  script_bugtraq_id(21078);
  script_xref(name:"RHSA", value:"2007:0356");

  script_name(english:"CentOS 3 / 4 / 5 : libpng (CESA-2007:0356)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng packages that fix security issues are now available for
Red Hat Enterprise Linux.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libpng package contains a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A flaw was found in the handling of malformed images in libpng. An
attacker could create a carefully crafted PNG image file in such a way
that it could cause an application linked with libpng to crash when
the file was manipulated. (CVE-2007-2445)

A flaw was found in the sPLT chunk handling code in libpng. An
attacker could create a carefully crafted PNG image file in such a way
that it could cause an application linked with libpng to crash when
the file was opened. (CVE-2006-5793)

Users of libpng should update to these updated packages which contain
backported patches to correct these issues.

Red Hat would like to thank Glenn Randers-Pehrson, Mats Palmgren, and
Tavis Ormandy for supplying details and patches for these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013780.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12a7bcdf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013781.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74d827b4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013790.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f5ac9bd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013791.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4242787"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013798.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?929c7680"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8b20877"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013810.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e83b1a7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb8a6900"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/20");
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
if (rpm_check(release:"CentOS-3", reference:"libpng-1.2.2-27")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libpng-devel-1.2.2-27")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libpng10-1.0.13-17")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libpng10-devel-1.0.13-17")) flag++;

if (rpm_check(release:"CentOS-4", reference:"libpng-1.2.7-3.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libpng-devel-1.2.7-3.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libpng10-1.0.16-3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libpng10-devel-1.0.16-3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libpng-1.2.10-7.0.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpng-devel-1.2.10-7.0.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng-devel / libpng10 / libpng10-devel");
}
