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
  script_id(73115);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-7243", "CVE-2009-0689");

  script_name(english:"Scientific Linux Security Update : php on SL5.x i386/x86_64 (20140318)");
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
"A buffer overflow flaw was found in the way PHP parsed floating point
numbers from their text representation. If a PHP application converted
untrusted input strings to numbers, an attacker able to provide such
input could cause the application to crash or, possibly, execute
arbitrary code with the privileges of the application. (CVE-2009-0689)

It was found that PHP did not properly handle file names with a NULL
character. A remote attacker could possibly use this flaw to make a
PHP script access unexpected files and bypass intended file system
access restrictions. (CVE-2006-7243)

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1403&L=scientific-linux-errata&T=0&P=1702
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb5e0b06"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");
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
if (rpm_check(release:"SL5", reference:"php-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-debuginfo-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-44.el5_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
}
