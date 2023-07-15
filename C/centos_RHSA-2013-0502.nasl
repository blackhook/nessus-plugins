#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0502 and 
# CentOS Errata and Security Advisory 2013:0502 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65137);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2504");
  script_bugtraq_id(58082);
  script_xref(name:"RHSA", value:"2013:0502");

  script_name(english:"CentOS 6 : xorg-x11-apps / xorg-x11-server-utils / xorg-x11-utils (CESA-2013:0502)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated core client packages for the X Window System that fix one
security issue, several bugs, and add various enhancements are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Core X11 clients packages provide the xorg-x11-utils,
xorg-x11-server-utils, and xorg-x11-apps clients that ship with the X
Window System.

It was found that the x11perfcomp utility included the current working
directory in its PATH environment variable. Running x11perfcomp in an
attacker-controlled directory would cause arbitrary code execution
with the privileges of the user running x11perfcomp. (CVE-2011-2504)

Also with this update, the xorg-x11-utils and xorg-x11-server-utils
packages have been upgraded to upstream version 7.5, and the
xorg-x11-apps package to upstream version 7.6, which provides a number
of bug fixes and enhancements over the previous versions. (BZ#835277,
BZ#835278, BZ#835281)

All users of xorg-x11-utils, xorg-x11-server-utils, and xorg-x11-apps
are advised to upgrade to these updated packages, which fix these
issues and add these enhancements."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019553.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac6be9b4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019604.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f699930f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019606.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f8f9d18"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000746.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcc62447"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000797.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5da857f0"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-February/000799.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad20c78d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected xorg-x11-apps, xorg-x11-server-utils and / or
xorg-x11-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2504");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-apps-7.6-6.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-utils-7.5-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-utils-7.5-6.el6")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-apps / xorg-x11-server-utils / xorg-x11-utils");
}
