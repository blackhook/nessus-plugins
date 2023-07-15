#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0630 and 
# CentOS Errata and Security Advisory 2017:0630 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97953);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-10207", "CVE-2017-5581");
  script_xref(name:"RHSA", value:"2017:0630");

  script_name(english:"CentOS 6 : tigervnc (CESA-2017:0630)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for tigervnc is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Virtual Network Computing (VNC) is a remote display system which
allows users to view a computing desktop environment not only on the
machine where it is running, but from anywhere on the Internet and
from a wide variety of machine architectures. TigerVNC is a suite of
VNC servers and clients. The tigervnc packages contain a client which
allows users to connect to other desktops running a VNC server.

Security Fix(es) :

* A denial of service flaw was found in the TigerVNC's Xvnc server. A
remote unauthenticated attacker could use this flaw to make Xvnc crash
by terminating the TLS handshake process early. (CVE-2016-10207)

* A buffer overflow flaw, leading to memory corruption, was found in
TigerVNC viewer. A remote malicious VNC server could use this flaw to
crash the client vncviewer process resulting in denial of service.
(CVE-2017-5581)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-March/003960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5ec02c1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tigervnc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5581");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"tigervnc-1.1.0-24.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tigervnc-server-1.1.0-24.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tigervnc-server-applet-1.1.0-24.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tigervnc-server-module-1.1.0-24.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tigervnc / tigervnc-server / tigervnc-server-applet / etc");
}
