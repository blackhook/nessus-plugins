#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0841 and 
# CentOS Errata and Security Advisory 2012:0841 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59924);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-4088", "CVE-2012-1106");
  script_xref(name:"RHSA", value:"2012:0841");

  script_name(english:"CentOS 6 : abrt (CESA-2012:0841)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated abrt, libreport, btparser, and python-meh packages that fix
two security issues and several bugs are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
defects in applications and to create a bug report with all the
information needed by a maintainer to fix it. It uses a plug-in system
to extend its functionality. libreport provides an API for reporting
different problems in applications to different bug targets, such as
Bugzilla, FTP, and Trac.

The btparser utility is a backtrace parser and analyzer library, which
works with backtraces produced by the GNU Project Debugger. It can
parse a text file with a backtrace to a tree of C structures, allowing
to analyze the threads and frames of the backtrace and process them.

The python-meh package provides a python library for handling
exceptions.

If the C handler plug-in in ABRT was enabled (the abrt-addon-ccpp
package installed and the abrt-ccpp service running), and the sysctl
fs.suid_dumpable option was set to '2' (it is '0' by default), core
dumps of set user ID (setuid) programs were created with insecure
group ID permissions. This could allow local, unprivileged users to
obtain sensitive information from the core dump files of setuid
processes they would otherwise not be able to access. (CVE-2012-1106)

ABRT did not allow users to easily search the collected crash
information for sensitive data prior to submitting it. This could lead
to users unintentionally exposing sensitive information via the
submitted crash reports. This update adds functionality to search
across all the collected data. Note that this fix does not apply to
the default configuration, where reports are sent to Red Hat Customer
Support. It only takes effect for users sending information to Red Hat
Bugzilla. (CVE-2011-4088)

Red Hat would like to thank Jan Iven for reporting CVE-2011-4088.

These updated packages include numerous bug fixes. Space precludes
documenting all of these changes in this advisory. Users are directed
to the Red Hat Enterprise Linux 6.3 Technical Notes for information on
the most significant of these changes.

All users of abrt, libreport, btparser, and python-meh are advised to
upgrade to these updated packages, which correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-July/018708.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd64de9e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected abrt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1106");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-ccpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-addon-vmcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:abrt-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:btparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:btparser-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:btparser-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"abrt-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-addon-ccpp-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-addon-kerneloops-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-addon-python-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-addon-vmcore-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-cli-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-desktop-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-devel-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-gui-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-libs-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"abrt-tui-2.0.8-6.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"btparser-0.16-3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"btparser-devel-0.16-3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"btparser-python-0.16-3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-cli-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-devel-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-gtk-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-gtk-devel-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-newt-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-bugzilla-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-kerneloops-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-logger-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-mailx-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-reportuploader-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-rhtsupport-2.0.9-5.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-python-2.0.9-5.el6.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / abrt-addon-ccpp / abrt-addon-kerneloops / abrt-addon-python / etc");
}
