#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0123 and 
# CentOS Errata and Security Advisory 2013:0123 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63568);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-4339");
  script_bugtraq_id(51036);
  script_xref(name:"RHSA", value:"2013:0123");

  script_name(english:"CentOS 5 : OpenIPMI (CESA-2013:0123)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenIPMI packages that fix one security issue, multiple bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The OpenIPMI packages provide command line tools and utilities to
access platform information using Intelligent Platform Management
Interface (IPMI). System administrators can use OpenIPMI to manage
systems and to perform system health monitoring.

It was discovered that the IPMI event daemon (ipmievd) created its
process ID (PID) file with world-writable permissions. A local user
could use this flaw to make the ipmievd init script kill an arbitrary
process when the ipmievd daemon is stopped or restarted.
(CVE-2011-4339)

Note: This issue did not affect the default configuration of OpenIPMI
as shipped with Red Hat Enterprise Linux 5.

This update also fixes the following bugs :

* Prior to this update, the ipmitool utility first checked the IPMI
hardware for Dell IPMI extensions and listed only supported commands
when printing command usage like the option 'ipmtool delloem help'. On
a non-Dell platform, the usage text was incomplete and misleading.
This update lists all Dell OEM extensions in usage texts on all
platforms, which allows users to check for command line arguments on
non-Dell hardware. (BZ#658762)

* Prior to this update, the ipmitool utility tried to retrieve the
Sensor Data Records (SDR) from the IPMI bus instead of the Baseboard
Management Controller (BMC) bus when IPMI-enabled devices reported SDR
under a different owner than the BMC. As a consequence, the timeout
setting for the SDR read attempt could significantly decrease the
performance and no sensor data was shown. This update modifies
ipmitool to read these SDR records from the BMC and shows the correct
sensor data on these platforms. (BZ#671059, BZ#749796)

* Prior to this update, the exit code of the 'ipmitool -o list' option
was not set correctly. As a consequence, 'ipmitool -o list' always
returned the value 1 instead of the expected value 0. This update
modifies the underlying code to return the value 0 as expected.
(BZ#740780)

* Prior to this update, the 'ipmi' service init script did not specify
the full path to the '/sbin/lsmod' and '/sbin/modprobe' system
utilities. As a consequence, the init script failed when it was
executed if PATH did not point to /sbin, for example, when running
'sudo /etc/init.d/ipmi'. This update modifies the init script so that
it now contains the full path to lsmod and modrpobe. Now, it can be
executed with sudo. (BZ#829705)

* Prior to this update, the ipmitool man page did not list the '-b',
'-B', '-l' and '-T' options. In this update, these options are
documented in the ipmitool man page. (BZ#846596)

This update also adds the following enhancement :

* Updates to the Dell-specific IPMI extension: A new vFlash command,
which allows users to display information about extended SD cards; a
new setled command, which allows users to display the backplane LED
status; improved error descriptions; added support for new hardware;
and updated documentation of the ipmitool delloem commands in the
ipmitool manual page. (BZ#797050)

All users of OpenIPMI are advised to upgrade to these updated
packages, which contain backported patches to correct these issues and
add this enhancement."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12a1d38a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-January/000407.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1de77de"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openipmi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-4339");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:OpenIPMI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:OpenIPMI-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:OpenIPMI-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:OpenIPMI-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:OpenIPMI-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:OpenIPMI-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:OpenIPMI-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"OpenIPMI-2.0.16-16.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"OpenIPMI-devel-2.0.16-16.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"OpenIPMI-gui-2.0.16-16.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"OpenIPMI-libs-2.0.16-16.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"OpenIPMI-perl-2.0.16-16.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"OpenIPMI-python-2.0.16-16.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"OpenIPMI-tools-2.0.16-16.el5")) flag++;


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
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenIPMI / OpenIPMI-devel / OpenIPMI-gui / OpenIPMI-libs / etc");
}
