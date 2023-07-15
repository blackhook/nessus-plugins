#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2505 and 
# CentOS Errata and Security Advisory 2015:2505 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87160);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-5273", "CVE-2015-5287", "CVE-2015-5302");
  script_xref(name:"RHSA", value:"2015:2505");

  script_name(english:"CentOS 7 : abrt / libreport (CESA-2015:2505)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated abrt and libreport packages that fix three security issues are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
defects in applications and to create a bug report with all the
information needed by a maintainer to fix it. It uses a plug-in system
to extend its functionality. libreport provides an API for reporting
different problems in applications to different bug targets, such as
Bugzilla, FTP, and Trac.

It was found that the ABRT debug information installer
(abrt-action-install-debuginfo-to-abrt-cache) did not use temporary
directories in a secure way. A local attacker could use the flaw to
create symbolic links and files at arbitrary locations as the abrt
user. (CVE-2015-5273)

It was discovered that the kernel-invoked coredump processor provided
by ABRT did not handle symbolic links correctly when writing core
dumps of ABRT programs to the ABRT dump directory (/var/spool/abrt). A
local attacker with write access to an ABRT problem directory could
use this flaw to escalate their privileges. (CVE-2015-5287)

It was found that ABRT may have exposed unintended information to Red
Hat Bugzilla during crash reporting. A bug in the libreport library
caused changes made by a user in files included in a crash report to
be discarded. As a result, Red Hat Bugzilla attachments may contain
data that was not intended to be made public, including host names, IP
addresses, or command line options. (CVE-2015-5302)

This flaw did not affect default installations of ABRT on Red Hat
Enterprise Linux as they do not post data to Red Hat Bugzilla. This
feature can however be enabled, potentially impacting modified ABRT
instances.

As a precaution, Red Hat has identified bugs filed by such non-default
Red Hat Enterprise Linux users of ABRT and marked them private.

Red Hat would like to thank Philip Pettersson of Samsung for reporting
the CVE-2015-5273 and CVE-2015-5287 issues. The CVE-2015-5302 issue
was discovered by Bastien Nocera of Red Hat.

All users of abrt and libreport are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-December/002721.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?753bfe88"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-December/002722.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?722dda93"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected abrt and / or libreport packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5287");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ABRT sosreport Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-ccpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-pstoreoops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-upload-watch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-vmcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-console-notification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-gui-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-python-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-retrace-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-anaconda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-centos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-mantisbt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-ureport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-rhel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-rhel-anaconda-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-rhel-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-web-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-addon-ccpp-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-addon-kerneloops-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-addon-pstoreoops-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-addon-python-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-addon-upload-watch-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-addon-vmcore-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-addon-xorg-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-cli-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-console-notification-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-dbus-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-desktop-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-devel-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-gui-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-gui-devel-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-gui-libs-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-libs-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-python-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-python-doc-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-retrace-client-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"abrt-tui-2.1.11-36.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-anaconda-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-centos-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-cli-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-compat-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-devel-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-filesystem-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-gtk-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-gtk-devel-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-newt-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-plugin-bugzilla-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-plugin-kerneloops-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-plugin-logger-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-plugin-mailx-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-plugin-mantisbt-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-plugin-reportuploader-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-plugin-rhtsupport-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-plugin-ureport-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-python-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-rhel-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-rhel-anaconda-bugzilla-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-rhel-bugzilla-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-web-2.1.11-32.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libreport-web-devel-2.1.11-32.el7.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / abrt-addon-ccpp / abrt-addon-kerneloops / etc");
}
