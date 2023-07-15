#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:802 and 
# CentOS Errata and Security Advisory 2005:802 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21862);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3178");
  script_bugtraq_id(15051);
  script_xref(name:"RHSA", value:"2005:802");

  script_name(english:"CentOS 3 / 4 : xloadimage (CESA-2005:802)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A new xloadimage package that fixes bugs in handling malformed tiff
and pbm/pnm/ppm images, and in handling metacharacters in file names
is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The xloadimage utility displays images in an X Window System window,
loads images into the root window, or writes images into a file.
Xloadimage supports many image types (including GIF, TIFF, JPEG, XPM,
and XBM).

A flaw was discovered in xloadimage via which an attacker can
construct a NIFF image with a very long embedded image title. This
image can cause a buffer overflow. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-3178
to this issue.

All users of xloadimage should upgrade to this erratum package, which
contains backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4743ec6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012309.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bea1d90"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bed9370"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012311.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0291a002"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012324.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c09b780"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-October/012325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b453b85a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xloadimage package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xloadimage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/18");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"xloadimage-4.1-36.RHEL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"xloadimage-4.1-36.RHEL4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xloadimage");
}
