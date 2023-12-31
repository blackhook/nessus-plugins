#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-563.
#

include("compat.inc");

if (description)
{
  script_id(84625);
  script_version("2.6");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2014-3416", "CVE-2015-2325", "CVE-2015-2326", "CVE-2015-3414", "CVE-2015-3415", "CVE-2015-4642", "CVE-2015-4643", "CVE-2015-4644");
  script_xref(name:"ALAS", value:"2015-563");

  script_name(english:"Amazon Linux AMI : php56 (ALAS-2015-563)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream reports that several bugs have been fixed as well as several
security issues into some bundled libraries (CVE-2015-3414 ,
CVE-2015-3415 , CVE-2015-3416 , CVE-2015-2325 and CVE-2015-2326). All
PHP 5.6 users are encouraged to upgrade to this version. Please see
the upstream release notes for full details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://php.net/ChangeLog-5.php#5.6.10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-563.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php56' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");
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
if (rpm_check(release:"ALA", reference:"php56-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-bcmath-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-cli-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-common-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dba-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dbg-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-debuginfo-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-devel-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-embedded-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-enchant-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-fpm-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gd-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gmp-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-imap-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-intl-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-ldap-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mbstring-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mcrypt-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mssql-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mysqlnd-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-odbc-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-opcache-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pdo-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pgsql-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-process-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pspell-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-recode-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-snmp-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-soap-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-tidy-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xml-5.6.10-1.115.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xmlrpc-5.6.10-1.115.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php56 / php56-bcmath / php56-cli / php56-common / php56-dba / etc");
}
