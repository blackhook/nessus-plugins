#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1284.
#

include("compat.inc");

if (description)
{
  script_id(129011);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2019-11041", "CVE-2019-11042");
  script_xref(name:"ALAS", value:"2019-1284");

  script_name(english:"Amazon Linux AMI : php72 (ALAS-2019-1284)");
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

When PHP EXIF extension is parsing EXIF information from an image,
e.g. via exif_read_data() function, in PHP versions 7.1.x below
7.1.31, 7.2.x below 7.2.21 and 7.3.x below 7.3.8 it is possible to
supply it with data what will cause it to read past the allocated
buffer. This may lead to information disclosure or
crash.(CVE-2019-11041)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1284.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php72' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-pdo-dblib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/09");
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
if (rpm_check(release:"ALA", reference:"php72-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-bcmath-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-cli-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-common-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-dba-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-dbg-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-debuginfo-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-devel-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-embedded-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-enchant-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-fpm-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-gd-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-gmp-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-imap-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-intl-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-json-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-ldap-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-mbstring-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-mysqlnd-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-odbc-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-opcache-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pdo-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pdo-dblib-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pgsql-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-process-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pspell-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-recode-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-snmp-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-soap-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-tidy-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-xml-7.2.21-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-xmlrpc-7.2.21-1.15.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php72 / php72-bcmath / php72-cli / php72-common / php72-dba / etc");
}
