#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-460.
#

include("compat.inc");

if (description)
{
  script_id(79874);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2014-8088", "CVE-2014-8089");
  script_xref(name:"ALAS", value:"2014-460");

  script_name(english:"Amazon Linux AMI : php-ZendFramework (ALAS-2014-460)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The (1) Zend_Ldap class in Zend before 1.12.9 and (2) Zend\Ldap
component in Zend 2.x before 2.2.8 and 2.3.x before 2.3.3 allows
remote attackers to bypass authentication via a password starting with
a null byte, which triggers an unauthenticated bind. (CVE-2014-8088)

The 1.12.9, 2.2.8, and 2.3.3 releases of the Zend Framework fix a SQL
injection issue when using the sqlsrv PHP extension. Full details are
available in the upstream advisory. (CVE-2014-8089)"
  );
  # http://framework.zend.com/security/advisory/ZF2014-06
  script_set_attribute(
    attribute:"see_also",
    value:"https://framework.zend.com/security/advisory/ZF2014-06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-460.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php-ZendFramework' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Auth-Adapter-Ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Cache-Backend-Apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Cache-Backend-Libmemcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Cache-Backend-Memcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Captcha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Db-Adapter-Mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Db-Adapter-Pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Db-Adapter-Pdo-Mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Db-Adapter-Pdo-Mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Db-Adapter-Pdo-Pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Dojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Feed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Search-Lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Serializer-Adapter-Igbinary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-Soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ZendFramework-full");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"php-ZendFramework-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Auth-Adapter-Ldap-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Cache-Backend-Apc-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Cache-Backend-Libmemcached-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Cache-Backend-Memcached-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Captcha-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Db-Adapter-Mysqli-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Db-Adapter-Pdo-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Db-Adapter-Pdo-Mssql-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Db-Adapter-Pdo-Mysql-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Db-Adapter-Pdo-Pgsql-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Dojo-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Feed-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Ldap-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Pdf-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Search-Lucene-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Serializer-Adapter-Igbinary-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Services-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-Soap-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-demos-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-extras-1.12.9-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ZendFramework-full-1.12.9-1.10.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-ZendFramework / php-ZendFramework-Auth-Adapter-Ldap / etc");
}
