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
  script_id(84394);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-8142", "CVE-2014-9652", "CVE-2014-9705", "CVE-2014-9709", "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-2301", "CVE-2015-2348", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3307", "CVE-2015-3329", "CVE-2015-3330", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025", "CVE-2015-4026", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4604", "CVE-2015-4605");

  script_name(english:"Scientific Linux Security Update : php on SL7.x x86_64 (20150623)");
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
"A flaw was found in the way the PHP module for the Apache httpd web
server handled pipelined requests. A remote attacker could use this
flaw to trigger the execution of a PHP script in a deinitialized
interpreter, causing it to crash or, possibly, execute arbitrary code.
(CVE-2015-3330)

A flaw was found in the way PHP parsed multipart HTTP POST requests. A
specially crafted request could cause PHP to use an excessive amount
of CPU time. (CVE-2015-4024)

An uninitialized pointer use flaw was found in PHP's Exif extension. A
specially crafted JPEG or TIFF file could cause a PHP application
using the exif_read_data() function to crash or, possibly, execute
arbitrary code with the privileges of the user running that PHP
application. (CVE-2015-0232)

An integer overflow flaw leading to a heap-based buffer overflow was
found in the way PHP's FTP extension parsed file listing FTP server
responses. A malicious FTP server could use this flaw to cause a PHP
application to crash or, possibly, execute arbitrary code.
(CVE-2015-4022)

Multiple flaws were discovered in the way PHP performed object
unserialization. Specially crafted input processed by the
unserialize() function could cause a PHP application to crash or,
possibly, execute arbitrary code. (CVE-2014-8142, CVE-2015-0231,
CVE-2015-0273, CVE-2015-2787, CVE-2015-4147, CVE-2015-4148,
CVE-2015-4599, CVE-2015-4600, CVE-2015-4601, CVE-2015-4602,
CVE-2015-4603)

It was found that certain PHP functions did not properly handle file
names containing a NULL character. A remote attacker could possibly
use this flaw to make a PHP script access unexpected files and bypass
intended file system access restrictions. (CVE-2015-2348,
CVE-2015-4025, CVE-2015-4026, CVE-2015-3411, CVE-2015-3412,
CVE-2015-4598)

Multiple flaws were found in the way the way PHP's Phar extension
parsed Phar archives. A specially crafted archive could cause PHP to
crash or, possibly, execute arbitrary code when opened.
(CVE-2015-2301, CVE-2015-2783, CVE-2015-3307, CVE-2015-3329,
CVE-2015-4021)

Multiple flaws were found in PHP's File Information (fileinfo)
extension. A remote attacker could cause a PHP application to crash if
it used fileinfo to identify type of attacker supplied files.
(CVE-2014-9652, CVE-2015-4604, CVE-2015-4605)

A heap buffer overflow flaw was found in the
enchant_broker_request_dict() function of PHP's enchant extension. An
attacker able to make a PHP application enchant dictionaries could
possibly cause it to crash. (CVE-2014-9705)

A buffer over-read flaw was found in the GD library used by the PHP gd
extension. A specially crafted GIF file could cause a PHP application
using the imagecreatefromgif() function to crash. (CVE-2014-9709)

This update also fixes the following bugs :

  - The libgmp library in some cases terminated unexpectedly
    with a segmentation fault when being used with other
    libraries that use the GMP memory management. With this
    update, PHP no longer changes libgmp memory allocators,
    which prevents the described crash from occurring.

  - When using the Open Database Connectivity (ODBC) API,
    the PHP process in some cases terminated unexpectedly
    with a segmentation fault. The underlying code has been
    adjusted to prevent this crash.

  - Previously, running PHP on a big-endian system sometimes
    led to memory corruption in the fileinfo module. This
    update adjusts the behavior of the PHP pointer so that
    it can be freed without causing memory corruption.

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=12640
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97d2de81"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/25");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-bcmath-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-cli-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-common-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-dba-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-debuginfo-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-devel-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-embedded-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-enchant-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-fpm-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-gd-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-intl-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-ldap-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mbstring-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mysql-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mysqlnd-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-odbc-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pdo-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pgsql-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-process-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pspell-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-recode-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-snmp-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-soap-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-xml-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-xmlrpc-5.4.16-36.el7_1")) flag++;


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
