#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-507.
#

include("compat.inc");

if (description)
{
  script_id(82835);
  script_version("1.8");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2015-0231", "CVE-2015-2305", "CVE-2015-2331");
  script_xref(name:"ALAS", value:"2015-507");

  script_name(english:"Amazon Linux AMI : php55 (ALAS-2015-507)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A use-after-free flaw was found in the way PHP's unserialize()
function processed data. If a remote attacker was able to pass crafted
input to PHP's unserialize() function, they could cause the PHP
interpreter to crash or, possibly, execute arbitrary code.
(CVE-2015-0231)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way libzip, which is also embedded in PHP, processed
certain ZIP archives. If an attacker were able to supply a specially
crafted ZIP archive to an application using libzip, it could cause the
application to crash or, possibly, execute arbitrary code.
(CVE-2015-2331)

Integer overflow in the regcomp implementation in the Henry Spencer
BSD regex library (aka rxspencer) alpha3.8.g5 on 32-bit platforms, as
used in NetBSD through 6.1.5 and other products, might allow
context-dependent attackers to execute arbitrary code via a large
regular expression that leads to a heap-based buffer overflow.
(CVE-2015-2305)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-507.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php55' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"php55-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-bcmath-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-cli-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-common-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-dba-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-debuginfo-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-devel-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-embedded-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-enchant-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-fpm-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-gd-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-gmp-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-imap-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-intl-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-ldap-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mbstring-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mcrypt-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mssql-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mysqlnd-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-odbc-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-opcache-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pdo-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pgsql-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-process-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pspell-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-recode-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-snmp-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-soap-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-tidy-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-xml-5.5.23-1.99.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-xmlrpc-5.5.23-1.99.amzn1")) flag++;

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
