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
  script_id(95854);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-5399", "CVE-2016-5766", "CVE-2016-5767", "CVE-2016-5768");

  script_name(english:"Scientific Linux Security Update : php on SL7.x x86_64 (20161103)");
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

  - A flaw was found in the way certain error conditions
    were handled by bzread() function in PHP. An attacker
    could use this flaw to upload a specially crafted bz2
    archive which, when parsed via the vulnerable function,
    could cause the application to crash or execute
    arbitrary code with the permissions of the user running
    the PHP application. (CVE-2016-5399)

  - An integer overflow flaw, leading to a heap-based buffer
    overflow was found in the imagecreatefromgd2() function
    of PHP's gd extension. A remote attacker could use this
    flaw to crash a PHP application or execute arbitrary
    code with the privileges of the user running that PHP
    application using gd via a specially crafted GD2 image.
    (CVE-2016-5766)

  - An integer overflow flaw, leading to a heap-based buffer
    overflow was found in the gdImagePaletteToTrueColor()
    function of PHP's gd extension. A remote attacker could
    use this flaw to crash a PHP application or execute
    arbitrary code with the privileges of the user running
    that PHP application using gd via a specially crafted
    image buffer. (CVE-2016-5767)

  - A double free flaw was found in the
    mb_ereg_replace_callback() function of php which is used
    to perform regex search. This flaw could possibly cause
    a PHP application to crash. (CVE-2016-5768)

Additional Changes :"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=6321
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ca54de8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-bcmath-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-cli-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-common-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-dba-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-debuginfo-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-devel-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-embedded-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-enchant-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-fpm-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-gd-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-intl-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-ldap-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mbstring-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mysql-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mysqlnd-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-odbc-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pdo-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pgsql-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-process-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pspell-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-recode-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-snmp-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-soap-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-xml-5.4.16-42.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-xmlrpc-5.4.16-42.el7")) flag++;


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
