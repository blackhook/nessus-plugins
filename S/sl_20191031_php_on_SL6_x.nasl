#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(130499);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-11043");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"Scientific Linux Security Update : php on SL6.x i386/x86_64 (20191031)");
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

  - php: underflow in env_path_info in fpm_main.c
    (CVE-2019-11043)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1911&L=SCIENTIFIC-LINUX-ERRATA&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1e27d3d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11043");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"php-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-bcmath-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-cli-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-common-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-dba-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-debuginfo-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-devel-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-embedded-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-enchant-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-fpm-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-gd-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-imap-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-intl-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-ldap-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-mbstring-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-mysql-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-odbc-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-pdo-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-pgsql-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-process-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-pspell-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-recode-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-snmp-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-soap-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-tidy-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-xml-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-xmlrpc-5.3.3-50.el6_10")) flag++;
if (rpm_check(release:"SL6", reference:"php-zts-5.3.3-50.el6_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
}
