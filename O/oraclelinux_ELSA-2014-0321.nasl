#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0321 and 
# Oracle Linux Security Advisory ELSA-2014-0321 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73172);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-2284");
  script_bugtraq_id(65867);
  script_xref(name:"RHSA", value:"2014:0321");

  script_name(english:"Oracle Linux 6 : net-snmp (ELSA-2014-0321)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0321 :

Updated net-snmp packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The net-snmp packages provide various libraries and tools for the
Simple Network Management Protocol (SNMP), including an SNMP library,
an extensible agent, tools for requesting or setting information from
SNMP agents, tools for generating and handling SNMP traps, a version
of the netstat command which uses SNMP, and a Tk/Perl Management
Information Base (MIB) browser.

A buffer overflow flaw was found in the way the decode_icmp_msg()
function in the ICMP-MIB implementation processed Internet Control
Message Protocol (ICMP) message statistics reported in the
/proc/net/snmp file. A remote attacker could send a message for each
ICMP message type, which could potentially cause the snmpd service to
crash when processing the /proc/net/snmp file. (CVE-2014-2284)

This update also fixes the following bug :

* The snmpd service parses the /proc/diskstats file to track disk
usage statistics for UCD-DISKIO-MIB::diskIOTable. On systems with a
large number of block devices, /proc/diskstats may be large in size
and parsing it can take a non-trivial amount of CPU time. With this
update, Net-SNMP introduces a new option, 'diskio', in the
/etc/snmp/snmpd.conf file, which can be used to explicitly specify
devices that should be monitored. Only these whitelisted devices are
then reported in UCD-DISKIO-MIB::diskIOTable, thus speeding up snmpd
on systems with numerous block devices. (BZ#990674)

All net-snmp users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the snmpd service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-March/004032.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"net-snmp-5.5-49.0.1.el6_5.1")) flag++;
if (rpm_check(release:"EL6", reference:"net-snmp-devel-5.5-49.0.1.el6_5.1")) flag++;
if (rpm_check(release:"EL6", reference:"net-snmp-libs-5.5-49.0.1.el6_5.1")) flag++;
if (rpm_check(release:"EL6", reference:"net-snmp-perl-5.5-49.0.1.el6_5.1")) flag++;
if (rpm_check(release:"EL6", reference:"net-snmp-python-5.5-49.0.1.el6_5.1")) flag++;
if (rpm_check(release:"EL6", reference:"net-snmp-utils-5.5-49.0.1.el6_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-devel / net-snmp-libs / net-snmp-perl / etc");
}
