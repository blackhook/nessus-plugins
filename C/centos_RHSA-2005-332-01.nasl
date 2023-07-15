#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:332 and 
# CentOS Errata and Security Advisory 2005:332-01 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67025);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0638");
  script_xref(name:"RHSA", value:"2005:332");

  script_name(english:"CentOS 3 : xloadimage (CESA-2005:332-01)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A new xloadimage package that fixes bugs in handling malformed tiff
and pbm/pnm/ppm images, and in handling metacharacters in filenames is
now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The xloadimage utility displays images in an X Window System window,
loads images into the root window, or writes images into a file.
Xloadimage supports many image types (including GIF, TIFF, JPEG, XPM,
and XBM).

A flaw was discovered in xloadimage where filenames were not properly
quoted when calling the gunzip command. An attacker could create a
file with a carefully crafted filename so that it would execute
arbitrary commands if opened by a victim. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-0638 to this issue.

Another bug in xloadimage would cause it to crash if called with
certain invalid TIFF, PNM, PBM, or PPM file names.

All users of xloadimage should upgrade to this erratum package which
contains backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011580.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e7c35a9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011581.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c46c9ec3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xloadimage package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xloadimage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"xloadimage-4.1-34.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"xloadimage-4.1-34.RHEL3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xloadimage");
}
