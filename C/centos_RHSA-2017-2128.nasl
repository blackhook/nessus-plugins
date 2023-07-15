#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2128 and 
# CentOS Errata and Security Advisory 2017:2128 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102753);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-7496");
  script_xref(name:"RHSA", value:"2017:2128");

  script_name(english:"CentOS 7 : gdm / gnome-session (CESA-2017:2128)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for gdm and gnome-session is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The GNOME Display Manager (GDM) provides the graphical login screen
shown shortly after boot up, log out, and when user-switching.

The following packages have been upgraded to a later upstream version:
gdm (3.22.3), gnome-session (3.22.3). (BZ#1386862, BZ#1386957)

Security Fix(es) :

* It was found that gdm could crash due to a signal handler dispatched
to an invalid conversation. An attacker could crash gdm by holding the
escape key when the screen is locked, possibly bypassing the locked
screen. (CVE-2015-7496)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.4 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004125.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9204a2aa"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004164.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?898211ad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdm and / or gnome-session packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7496");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-custom-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-session-xsession");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdm-3.22.3-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdm-devel-3.22.3-11.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-session-3.22.3-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-session-custom-session-3.22.3-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnome-session-xsession-3.22.3-4.el7")) flag++;


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
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-devel / gnome-session / gnome-session-custom-session / etc");
}
