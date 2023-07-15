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
  script_id(73177);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-2284");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL6.x i386/x86_64 (20140324)");
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
"A buffer overflow flaw was found in the way the decode_icmp_msg()
function in the ICMP-MIB implementation processed Internet Control
Message Protocol (ICMP) message statistics reported in the
/proc/net/snmp file. A remote attacker could send a message for each
ICMP message type, which could potentially cause the snmpd service to
crash when processing the /proc/net/snmp file. (CVE-2014-2284)

This update also fixes the following bug :

  - The snmpd service parses the /proc/diskstats file to
    track disk usage statistics for
    UCD-DISKIO-MIB::diskIOTable. On systems with a large
    number of block devices, /proc/diskstats may be large in
    size and parsing it can take a non-trivial amount of CPU
    time. With this update, Net-SNMP introduces a new
    option, 'diskio', in the /etc/snmp/snmpd.conf file,
    which can be used to explicitly specify devices that
    should be monitored. Only these whitelisted devices are
    then reported in UCD-DISKIO- MIB::diskIOTable, thus
    speeding up snmpd on systems with numerous block
    devices.

After installing this update, the snmpd service will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1403&L=scientific-linux-errata&T=0&P=2089
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?307b381f"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"net-snmp-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-debuginfo-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-devel-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-libs-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-perl-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-python-5.5-49.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"net-snmp-utils-5.5-49.el6_5.1")) flag++;


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
