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
  script_id(85202);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3565");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL6.x i386/x86_64 (20150722)");
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

  - The HOST-RESOURCES-MIB::hrSystemProcesses object was not
    implemented because parts of the HOST-RESOURCES-MIB
    module were rewritten in an earlier version of net-snmp.
    Consequently, HOST-RESOURCES- MIB::hrSystemProcesses did
    not provide information on the number of currently
    loaded or running processes. With this update,
    HOST-RESOURCES- MIB::hrSystemProcesses has been
    implemented, and the net-snmp daemon reports as
    expected.

  - The Net-SNMP agent daemon, snmpd, reloaded the system
    ARP table every 60 seconds. As a consequence, snmpd
    could cause a short CPU usage spike on busy systems with
    a large APR table. With this update, snmpd does not
    reload the full ARP table periodically, but monitors the
    table changes using a netlink socket.

  - Previously, snmpd used an invalid pointer to the current
    time when periodically checking certain conditions
    specified by the 'monitor' option in the
    /etc/snmpd/snmpd.conf file. Consequently, snmpd
    terminated unexpectedly on start with a segmentation
    fault if a certain entry with the 'monitor' option was
    used. Now, snmpd initializes the correct pointer to the
    current time, and snmpd no longer crashes on start.

  - Previously, snmpd expected 8-bit network interface
    indices when processing
    HOST-RESOURCES-MIB::hrDeviceTable. If an interface index
    of a local network interface was larger than 30,000
    items, snmpd could terminate unexpectedly due to
    accessing invalid memory. Now, processing of all network
    sizes is enabled, and snmpd no longer crashes in the
    described situation.

  - The snmpdtrapd service incorrectly checked for errors
    when forwarding a trap with a RequestID value of 0, and
    logged 'Forward failed' even though the trap was
    successfully forwarded. This update fixes snmptrapd
    checks and the aforementioned message is now logged only
    when appropriate.

  - Previously, snmpd ignored the value of the
    'storageUseNFS' option in the /etc/snmpd/snmpd.conf
    file. As a consequence, NFS drivers were shown as
    'Network Disks', even though 'storageUseNFS' was set to
    '2' to report them as 'Fixed Disks' in
    HOST-RESOURCES-MIB::hrStorageTable. With this update,
    snmpd takes the 'storageUseNFS' option value into
    account, and 'Fixed Disks' NFS drives are reported
    correctly.

  - Previously, the Net-SNMP python binding used an
    incorrect size (8 bytes instead of 4) for variables of
    IPADDRESS type. Consequently, applications that were
    using Net-SNMP Python bindings could send malformed SNMP
    messages. With this update, the bindings now use 4 bytes
    for variables with IPADRESS type, and only valid SNMP
    messages are sent.

  - Previously, the snmpd service did not cut values in
    HOST-RESOURCES- MIB::hrStorageTable to signed 32-bit
    integers, as required by SNMP standards, and provided
    the values as unsigned integers. As a consequence, the
    HOST-RESOURCES-MIB::hrStorageTable implementation did
    not conform to RFC 2790. The values are now cut to
    32-bit signed integers, and snmpd is therefore standard
    compliant."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=5847
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b632e971"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"net-snmp-5.5-54.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-debuginfo-5.5-54.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-devel-5.5-54.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-libs-5.5-54.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-perl-5.5-54.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-python-5.5-54.el6")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-utils-5.5-54.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-debuginfo / net-snmp-devel / net-snmp-libs / etc");
}
