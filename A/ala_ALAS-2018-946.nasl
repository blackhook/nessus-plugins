#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-946.
#

include("compat.inc");

if (description)
{
  script_id(106691);
  script_version("3.7");
  script_cvs_date("Date: 2018/06/28 13:49:39");

  script_cve_id("CVE-2018-5711", "CVE-2018-5712");
  script_xref(name:"ALAS", value:"2018-946");

  script_name(english:"Amazon Linux AMI : php56 / php70,php71 (ALAS-2018-946)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Reflected XSS in .phar 404 page

An issue was discovered in PHP; there is Reflected XSS on the PHAR 404
error page via the URI of a request for a .phar file. (CVE-2018-5712)

Denial of Service (DoS) via infinite loop in libgd
gdImageCreateFromGifCtx function in ext/gd/libgd/gd_gif_in.c

The gd_gif_in.c file in the GD Graphics Library (aka libgd), as used
in PHP has an integer signedness error that leads to an infinite loop
via a crafted GIF file, as demonstrated by a call to the
imagecreatefromgif or imagecreatefromstring PHP function. This is
related to GetCode_ and gdImageCreateFromGifCtx. (CVE-2018-5711)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-946.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update php56' to update your system.

Run 'yum update php70' to update your system.

Run 'yum update php71' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pdo-dblib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-zip");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"php56-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-bcmath-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-cli-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-common-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dba-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dbg-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-debuginfo-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-devel-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-embedded-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-enchant-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-fpm-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gd-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gmp-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-imap-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-intl-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-ldap-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mbstring-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mcrypt-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mssql-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mysqlnd-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-odbc-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-opcache-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pdo-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pgsql-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-process-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pspell-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-recode-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-snmp-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-soap-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-tidy-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xml-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xmlrpc-5.6.33-1.136.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-bcmath-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-cli-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-common-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-dba-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-dbg-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-debuginfo-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-devel-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-embedded-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-enchant-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-fpm-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-gd-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-gmp-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-imap-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-intl-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-json-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-ldap-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-mbstring-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-mcrypt-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-mysqlnd-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-odbc-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-opcache-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pdo-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pdo-dblib-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pgsql-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-process-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pspell-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-recode-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-snmp-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-soap-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-tidy-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-xml-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-xmlrpc-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-zip-7.0.27-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-bcmath-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-cli-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-common-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-dba-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-dbg-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-debuginfo-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-devel-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-embedded-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-enchant-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-fpm-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-gd-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-gmp-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-imap-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-intl-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-json-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-ldap-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-mbstring-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-mcrypt-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-mysqlnd-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-odbc-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-opcache-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pdo-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pdo-dblib-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pgsql-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-process-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pspell-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-recode-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-snmp-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-soap-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-tidy-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-xml-7.1.13-1.30.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-xmlrpc-7.1.13-1.30.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php56 / php56-bcmath / php56-cli / php56-common / php56-dba / etc");
}
