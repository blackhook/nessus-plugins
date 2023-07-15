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
  script_id(78460);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3634");

  script_name(english:"Scientific Linux Security Update : rsyslog on SL7.x x86_64 (20141013)");
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
"A flaw was found in the way rsyslog handled invalid log message
priority values. In certain configurations, a local attacker, or a
remote attacker able to connect to the rsyslog port, could use this
flaw to crash the rsyslog daemon or, potentially, execute arbitrary
code as the user running the rsyslog daemon. (CVE-2014-3634)

After installing the update, the rsyslog service will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1410&L=scientific-linux-errata&T=0&P=813
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?948ce39f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-libdbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmsnmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-udpspoof");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-crypto-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-debuginfo-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-doc-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-elasticsearch-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-gnutls-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-gssapi-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-libdbi-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mmaudit-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mmjsonparse-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mmnormalize-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mmsnmptrapd-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mysql-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-pgsql-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-relp-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-snmp-7.4.7-7.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-udpspoof-7.4.7-7.el7_0")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-crypto / rsyslog-debuginfo / rsyslog-doc / etc");
}
