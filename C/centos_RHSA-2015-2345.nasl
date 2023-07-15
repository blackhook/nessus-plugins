#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2345 and 
# CentOS Errata and Security Advisory 2015:2345 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87150);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3565");
  script_xref(name:"RHSA", value:"2015:2345");

  script_name(english:"CentOS 7 : net-snmp (CESA-2015:2345)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated net-snmp packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The net-snmp packages provide various libraries and tools for the
Simple Network Management Protocol (SNMP), including an SNMP library,
an extensible agent, tools for requesting or setting information from
SNMP agents, tools for generating and handling SNMP traps, a version
of the netstat command which uses SNMP, and a Tk/Perl Management
Information Base (MIB) browser.

A denial of service flaw was found in the way snmptrapd handled
certain SNMP traps when started with the '-OQ' option. If an attacker
sent an SNMP trap containing a variable with a NULL type where an
integer variable type was expected, it would cause snmptrapd to crash.
(CVE-2014-3565)

This update also fixes the following bugs :

* Previously, the clientaddr option in the snmp.conf file affected
outgoing messages sent only over IPv4. With this release, outgoing
IPv6 messages are correctly sent from the interface specified by
clientaddr. (BZ#1190679)

* The Net-SNMP daemon, snmpd, did not properly clean memory when
reloading its configuration file with multiple 'exec' entries.
Consequently, the daemon terminated unexpectedly. Now, the memory is
properly cleaned, and snmpd no longer crashes on reload. (BZ#1228893)

* Prior to this update, snmpd did not parse complete IPv4 traffic
statistics, but reported the number of received or sent bytes in the
IP-MIB::ipSystemStatsTable only for IPv6 packets and not for IPv4.
This affected objects ipSystemStatsInOctets, ipSystemStatsOutOctets,
ipSystemStatsInMcastOctets, and ipSystemStatsOutMcastOctets. Now, the
statistics reported by snmpd are collected for IPv4 as well.
(BZ#1235697)

* The Net-SNMP daemon, snmpd, did not correctly detect the file system
change from read-only to read-write. Consequently, after remounting
the file system into the read-write mode, the daemon reported it to be
still in the read-only mode. A patch has been applied, and snmpd now
detects the mode changes as expected. (BZ#1241897)

All net-snmp users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002499.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?470fa992"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3565");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-agent-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-5.7.2-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-agent-libs-5.7.2-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-devel-5.7.2-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-gui-5.7.2-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-libs-5.7.2-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-perl-5.7.2-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-python-5.7.2-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-sysvinit-5.7.2-24.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"net-snmp-utils-5.7.2-24.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-agent-libs / net-snmp-devel / net-snmp-gui / etc");
}
