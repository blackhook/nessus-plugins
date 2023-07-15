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
  script_id(73176);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-6151", "CVE-2014-2285");

  script_name(english:"Scientific Linux Security Update : net-snmp on SL5.x i386/x86_64 (20140324)");
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
"A denial of service flaw was found in the way snmpd, the Net-SNMP
daemon, handled subagent timeouts. A remote attacker able to trigger a
subagent timeout could use this flaw to cause snmpd to loop infinitely
or crash. (CVE-2012-6151)

A denial of service flaw was found in the way the snmptrapd service,
which receives and logs SNMP trap messages, handled SNMP trap requests
with an empty community string when the Perl handler (provided by the
net-snmp- perl package) was enabled. A remote attacker could use this
flaw to crash snmptrapd by sending a trap request with an empty
community string. (CVE-2014-2285)

After installing this update, the snmpd and snmptrapd services will be
restarted automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1403&L=scientific-linux-errata&T=0&P=1962
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98960127"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/13");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"net-snmp-5.3.2.2-22.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-debuginfo-5.3.2.2-22.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-devel-5.3.2.2-22.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-libs-5.3.2.2-22.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-perl-5.3.2.2-22.el5_10.1")) flag++;
if (rpm_check(release:"SL5", reference:"net-snmp-utils-5.3.2.2-22.el5_10.1")) flag++;


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
