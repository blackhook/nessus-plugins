#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-728.
#

include("compat.inc");

if (description)
{
  script_id(92663);
  script_version("2.9");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2015-8874", "CVE-2016-5385", "CVE-2016-5766", "CVE-2016-5767", "CVE-2016-5768", "CVE-2016-5769", "CVE-2016-5770", "CVE-2016-5771", "CVE-2016-5772", "CVE-2016-5773");
  script_xref(name:"ALAS", value:"2016-728");

  script_name(english:"Amazon Linux AMI : php55 / php56 (ALAS-2016-728) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack consumption vulnerability in GD in PHP allows remote attackers
to cause a denial of service via a crafted imagefilltoborder call.
(CVE-2015-8874)

An integer overflow, leading to a heap-based buffer overflow was found
in the imagecreatefromgd2() function of PHP's gd extension. A remote
attacker could use this flaw to crash a PHP application or execute
arbitrary code with the privileges of the user running that PHP
application, using gd via a specially crafted GD2 image.
(CVE-2016-5766)

An integer overflow, leading to a heap-based buffer overflow was found
in the gdImagePaletteToTrueColor() function of PHP's gd extension. A
remote attacker could use this flaw to crash a PHP application or
execute arbitrary code with the privileges of the user running that
PHP application, using gd via a specially crafted image buffer.
(CVE-2016-5767)

A double free flaw was found in the mb_ereg_replace_callback()
function of php which is used to perform regex search. This flaw could
possibly cause a PHP application to crash. (CVE-2016-5768)

The mcrypt_generic() and mdecrypt_generic() functions are prone to
integer overflows, resulting in a heap-based overflow. A remote
attacker could use this flaw to crash a PHP application or execute
arbitrary code with the privileges of the user running that PHP
application. (CVE-2016-5769)

A type confusion issue was found in the SPLFileObject fread()
function. A remote attacker able to submit a specially crafted input
to a PHP application, which uses this function, could use this flaw to
execute arbitrary code with the privileges of the user running that
PHP application. (CVE-2016-5770)

A use-after-free vulnerability that can occur when calling
unserialize() on untrusted input was discovered. A remote attacker
could use this flaw to crash a PHP application or execute arbitrary
code with the privileges of the user running that PHP application if
the application unserializes untrusted input. (CVE-2016-5771 ,
CVE-2016-5773)

A double free can occur in wddx_deserialize() when trying to
deserialize malicious XML input from user's request. This flaw could
possibly cause a PHP application to crash. (CVE-2016-5772)

It was discovered that PHP did not properly protect against the
HTTP_PROXY variable name clash. A remote attacker could possibly use
this flaw to redirect HTTP requests performed by a PHP script to an
attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-5385)

(Updated on 2016-08-17: CVE-2016-5385 was fixed in this release but
was not previously part of this errata)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-728.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update php55' to update your system.

Run 'yum update php56' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"php55-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-bcmath-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-cli-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-common-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-dba-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-debuginfo-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-devel-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-embedded-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-enchant-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-fpm-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-gd-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-gmp-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-imap-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-intl-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-ldap-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mbstring-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mcrypt-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mssql-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mysqlnd-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-odbc-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-opcache-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pdo-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pgsql-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-process-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pspell-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-recode-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-snmp-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-soap-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-tidy-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-xml-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-xmlrpc-5.5.38-1.116.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-bcmath-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-cli-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-common-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dba-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dbg-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-debuginfo-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-devel-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-embedded-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-enchant-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-fpm-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gd-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gmp-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-imap-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-intl-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-ldap-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mbstring-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mcrypt-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mssql-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mysqlnd-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-odbc-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-opcache-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pdo-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pgsql-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-process-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pspell-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-recode-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-snmp-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-soap-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-tidy-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xml-5.6.24-1.126.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xmlrpc-5.6.24-1.126.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php55 / php55-bcmath / php55-cli / php55-common / php55-dba / etc");
}
