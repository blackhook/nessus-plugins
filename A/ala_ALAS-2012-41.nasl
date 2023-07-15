#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-41.
#

include("compat.inc");

if (description)
{
  script_id(69648);
  script_version("1.6");
  script_cvs_date("Date: 2018/04/18 15:09:34");

  script_cve_id("CVE-2012-0830");
  script_xref(name:"ALAS", value:"2012-41");
  script_xref(name:"RHSA", value:"2012:0093");

  script_name(english:"Amazon Linux AMI : php (ALAS-2012-41)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the fix for CVE-2011-4885 introduced an
uninitialized memory use flaw. A remote attacker could send a
specially crafted HTTP request to cause the PHP interpreter to crash
or, possibly, execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-41.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"php-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-bcmath-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-cli-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-common-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-dba-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-debuginfo-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-devel-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-embedded-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-fpm-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-gd-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-imap-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-intl-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ldap-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mbstring-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mcrypt-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mssql-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mysql-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mysqlnd-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-odbc-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pdo-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pgsql-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-process-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pspell-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-snmp-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-soap-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-tidy-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-xml-5.3.10-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-xmlrpc-5.3.10-1.15.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
}
