#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87562);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3565");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL7.x x86_64 (20151119)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service flaw was found in the way snmptrapd handled
certain SNMP traps when started with the '-OQ' option. If an attacker
sent an SNMP trap containing a variable with a NULL type where an
integer variable type was expected, it would cause snmptrapd to crash.
(CVE-2014-3565)

This update also fixes the following bugs :

  - Previously, the clientaddr option in the snmp.conf file
    affected outgoing messages sent only over IPv4. With
    this release, outgoing IPv6 messages are correctly sent
    from the interface specified by clientaddr.

  - The Net-SNMP daemon, snmpd, did not properly clean
    memory when reloading its configuration file with
    multiple 'exec' entries. Consequently, the daemon
    terminated unexpectedly. Now, the memory is properly
    cleaned, and snmpd no longer crashes on reload.

  - Prior to this update, snmpd did not parse complete IPv4
    traffic statistics, but reported the number of received
    or sent bytes in the IP- MIB::ipSystemStatsTable only
    for IPv6 packets and not for IPv4. This affected objects
    ipSystemStatsInOctets, ipSystemStatsOutOctets,
    ipSystemStatsInMcastOctets, and
    ipSystemStatsOutMcastOctets. Now, the statistics
    reported by snmpd are collected for IPv4 as well.

  - The Net-SNMP daemon, snmpd, did not correctly detect the
    file system change from read-only to read-write.
    Consequently, after remounting the file system into the
    read-write mode, the daemon reported it to be still in
    the read-only mode. A patch has been applied, and snmpd
    now detects the mode changes as expected."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=6297
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f62acd4b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-agent-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-agent-libs-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-debuginfo-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-devel-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-gui-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-libs-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-perl-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-python-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-sysvinit-5.7.2-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"net-snmp-utils-5.7.2-24.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-agent-libs / net-snmp-debuginfo / etc");
}
