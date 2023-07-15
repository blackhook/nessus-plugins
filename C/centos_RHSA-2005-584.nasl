#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:584 and 
# CentOS Errata and Security Advisory 2005:584 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21948);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1849");
  script_xref(name:"RHSA", value:"2005:584");

  script_name(english:"CentOS 4 : zlib (CESA-2005:584)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated zlib packages that fix a buffer overflow are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Zlib is a general-purpose lossless data compression library that is
used by many different programs.

A previous zlib update, RHSA-2005:569 (CVE-2005-2096) fixed a flaw in
zlib that could allow a carefully crafted compressed stream to crash
an application. While the original patch corrected the reported
overflow, Markus Oberhumer discovered additional ways a stream could
trigger an overflow. An attacker could create a carefully crafted
compressed stream that would cause an application to crash if the
stream is opened by a user. As an example, an attacker could create a
malicious PNG image file that would cause a Web browser or mail viewer
to crash if the image is viewed. The Common Vulnerabilities and
Exposures project (cve.mitre.org) assigned the name CVE-2005-1849 to
this issue.

Note that the versions of zlib shipped with Red Hat Enterprise Linux
2.1 and 3 are not vulnerable to this issue.

All users should update to these errata packages that contain a patch
from Mark Adler that corrects this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011941.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f49e86de"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011955.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b00d4fa5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011956.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92704b10"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected zlib packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:zlib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/23");
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
if (rpm_check(release:"CentOS-4", reference:"zlib-1.2.1.2-1.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"zlib-devel-1.2.1.2-1.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zlib / zlib-devel");
}
