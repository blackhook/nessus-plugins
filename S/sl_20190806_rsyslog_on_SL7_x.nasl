#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(128259);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-16881");

  script_name(english:"Scientific Linux Security Update : rsyslog on SL7.x x86_64 (20190806)");
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
"Security Fix(es) :

  - rsyslog: imptcp: integer overflow when Octet-Counted TCP
    Framing is enabled (CVE-2018-16881)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=21751
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5678b65"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-kafka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-libdbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmjsonparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmkubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmnormalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mmsnmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-relp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:rsyslog-udpspoof");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-crypto-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-debuginfo-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", reference:"rsyslog-doc-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-doc-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-elasticsearch-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-gnutls-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-gssapi-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-kafka-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-libdbi-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mmaudit-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mmjsonparse-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mmkubernetes-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mmnormalize-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mmsnmptrapd-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-mysql-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-pgsql-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-relp-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-snmp-8.24.0-38.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rsyslog-udpspoof-8.24.0-38.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsyslog / rsyslog-crypto / rsyslog-debuginfo / rsyslog-doc / etc");
}
