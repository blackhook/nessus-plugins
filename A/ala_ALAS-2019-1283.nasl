#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1283.
#

include("compat.inc");

if (description)
{
  script_id(129010);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2019-11041", "CVE-2019-11042", "CVE-2019-13224");
  script_xref(name:"ALAS", value:"2019-1283");

  script_name(english:"Amazon Linux AMI : php71 / php73 (ALAS-2019-1283)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"When PHP EXIF extension is parsing EXIF information from an image,
e.g. via exif_read_data() function, in PHP versions 7.1.x below
7.1.31, 7.2.x below 7.2.21 and 7.3.x below 7.3.8 it is possible to
supply it with data what will cause it to read past the allocated
buffer. This may lead to information disclosure or
crash.(CVE-2019-11042)

A use-after-free in onig_new_deluxe() in regext.c in Oniguruma 6.9.2
allows attackers to potentially cause information disclosure, denial
of service, or possibly code execution by providing a crafted regular
expression. The attacker provides a pair of a regex pattern and a
string, with a multi-byte encoding that gets handled by
onig_new_deluxe(). Oniguruma issues often affect Ruby, as well as
common optional libraries for PHP and Rust.(CVE-2019-13224)

When PHP EXIF extension is parsing EXIF information from an image,
e.g. via exif_read_data() function, in PHP versions 7.1.x below
7.1.31, 7.2.x below 7.2.21 and 7.3.x below 7.3.8 it is possible to
supply it with data what will cause it to read past the allocated
buffer. This may lead to information disclosure or
crash.(CVE-2019-11041)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1283.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update php71' to update your system.

Run 'yum update php73' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-pdo-dblib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-pdo-dblib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php73-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"php71-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-bcmath-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-cli-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-common-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-dba-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-dbg-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-debuginfo-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-devel-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-embedded-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-enchant-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-fpm-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-gd-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-gmp-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-imap-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-intl-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-json-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-ldap-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-mbstring-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-mcrypt-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-mysqlnd-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-odbc-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-opcache-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pdo-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pdo-dblib-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pgsql-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-process-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pspell-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-recode-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-snmp-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-soap-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-tidy-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-xml-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-xmlrpc-7.1.31-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-bcmath-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-cli-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-common-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-dba-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-dbg-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-debuginfo-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-devel-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-embedded-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-enchant-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-fpm-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-gd-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-gmp-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-imap-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-intl-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-json-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-ldap-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-mbstring-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-mysqlnd-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-odbc-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-opcache-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pdo-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pdo-dblib-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pgsql-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-process-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pspell-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-recode-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-snmp-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-soap-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-tidy-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-xml-7.3.8-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-xmlrpc-7.3.8-1.18.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php71 / php71-bcmath / php71-cli / php71-common / php71-dba / etc");
}
