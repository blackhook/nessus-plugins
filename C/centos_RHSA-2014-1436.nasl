#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1436 and 
# CentOS Errata and Security Advisory 2014:1436 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79182);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1995", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2063", "CVE-2013-2064", "CVE-2013-2066");
  script_bugtraq_id(60120, 60121, 60122, 60123, 60124, 60125, 60126, 60127, 60128, 60129, 60131, 60132, 60133, 60134, 60135, 60136, 60137, 60138, 60139, 60143, 60144, 60145, 60146, 60148);
  script_xref(name:"RHSA", value:"2014:1436");

  script_name(english:"CentOS 6 : libX11 / libXcursor / libXext / libXfixes / libXi / libXinerama / libXp / libXrandr / etc (CESA-2014:1436)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated X11 client libraries packages that fix multiple security
issues, several bugs, and add various enhancements are now available
for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The X11 (Xorg) libraries provide library routines that are used within
all X Window applications.

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the way various X11 client libraries handled
certain protocol data. An attacker able to submit invalid protocol
data to an X11 server via a malicious X11 client could use either of
these flaws to potentially escalate their privileges on the system.
(CVE-2013-1981, CVE-2013-1982, CVE-2013-1983, CVE-2013-1984,
CVE-2013-1985, CVE-2013-1986, CVE-2013-1987, CVE-2013-1988,
CVE-2013-1989, CVE-2013-1990, CVE-2013-1991, CVE-2013-2003,
CVE-2013-2062, CVE-2013-2064)

Multiple array index errors, leading to heap-based buffer
out-of-bounds write flaws, were found in the way various X11 client
libraries handled data returned from an X11 server. A malicious X11
server could possibly use this flaw to execute arbitrary code with the
privileges of the user running an X11 client. (CVE-2013-1997,
CVE-2013-1998, CVE-2013-1999, CVE-2013-2000, CVE-2013-2001,
CVE-2013-2002, CVE-2013-2066)

A buffer overflow flaw was found in the way the XListInputDevices()
function of X.Org X11's libXi runtime library handled signed numbers.
A malicious X11 server could possibly use this flaw to execute
arbitrary code with the privileges of the user running an X11 client.
(CVE-2013-1995)

A flaw was found in the way the X.Org X11 libXt runtime library used
uninitialized pointers. A malicious X11 server could possibly use this
flaw to execute arbitrary code with the privileges of the user running
an X11 client. (CVE-2013-2005)

Two stack-based buffer overflow flaws were found in the way libX11,
the Core X11 protocol client library, processed certain user-specified
files. A malicious X11 server could possibly use this flaw to crash an
X11 client via a specially crafted file. (CVE-2013-2004)

The xkeyboard-config package has been upgraded to upstream version
2.11, which provides a number of bug fixes and enhancements over the
previous version. (BZ#1077471)

This update also fixes the following bugs :

* Previously, updating the mesa-libGL package did not update the
libX11 package, although it was listed as a dependency of mesa-libGL.
This bug has been fixed and updating mesa-libGL now updates all
dependent packages as expected. (BZ#1054614)

* Previously, closing a customer application could occasionally cause
the X Server to terminate unexpectedly. After this update, the X
Server no longer hangs when a user closes a customer application.
(BZ#971626)

All X11 client libraries users are advised to upgrade to these updated
packages, which correct these issues and add these enhancements."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001233.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b79cc02"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01c3d512"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20d1cc19"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de1e7678"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001267.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c5e9be1"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7db4ea17"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc226c84"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2db4cd33"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001271.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d22dfbb"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001272.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?501edd75"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed66b158"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001274.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08882ff6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001275.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4e0bef2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001276.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?366095e8"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001277.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?405b97cb"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001278.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b76f6a57"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001279.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02385819"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001280.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb5d4eea"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001399.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d465ad21"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001406.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d752e61c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001457.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7aa0b43"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001460.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?391fbefa"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1981");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXext-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfixes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXinerama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXinerama-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXrandr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXres-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXtst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXtst-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXvMC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXvMC-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXxf86dga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXxf86dga-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXxf86vm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXxf86vm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdmx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxcb-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xtrans-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"libX11-1.6.0-2.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libX11-common-1.6.0-2.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libX11-devel-1.6.0-2.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXcursor-1.1.14-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXcursor-devel-1.1.14-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXext-1.3.2-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXext-devel-1.3.2-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXfixes-5.0.1-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXfixes-devel-5.0.1-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXi-1.7.2-2.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXi-devel-1.7.2-2.2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXinerama-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXinerama-devel-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXp-1.0.2-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXp-devel-1.0.2-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXrandr-1.4.1-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXrandr-devel-1.4.1-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXrender-0.9.8-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXrender-devel-0.9.8-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXres-1.0.7-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXres-devel-1.0.7-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXt-1.1.4-6.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXt-devel-1.1.4-6.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXtst-1.2.2-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXtst-devel-1.2.2-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXv-1.0.9-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXv-devel-1.0.9-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXvMC-1.0.8-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXvMC-devel-1.0.8-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXxf86dga-1.1.4-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXxf86dga-devel-1.1.4-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXxf86vm-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXxf86vm-devel-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libdmx-1.1.3-3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libdmx-devel-1.1.3-3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxcb-1.9.1-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxcb-devel-1.9.1-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxcb-doc-1.9.1-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxcb-python-1.9.1-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xcb-proto-1.8-3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xkeyboard-config-2.11-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xkeyboard-config-devel-2.11-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-proto-devel-7.7-9.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-xtrans-devel-1.3.4-1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libX11 / libX11-common / libX11-devel / libXcursor / etc");
}
