#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1350.
#

include("compat.inc");

if (description)
{
  script_id(134572);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/18");

  script_cve_id("CVE-2020-7061", "CVE-2020-7062", "CVE-2020-7063");
  script_xref(name:"ALAS", value:"2020-1350");

  script_name(english:"Amazon Linux AMI : php72 (ALAS-2020-1350)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In PHP versions 7.3.x below 7.3.15 and 7.4.x below 7.4.3, while
extracting PHAR files on Windows using phar extension, certain content
inside PHAR file could lead to one-byte read past the allocated
buffer. This could potentially lead to information disclosure or
crash. (CVE-2020-7061)

In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15 and 7.4.x below
7.4.3, when using file upload functionality, if upload progress
tracking is enabled, but session.upload_progress.cleanup is set to 0
(disabled), and the file upload fails, the upload procedure would try
to clean up data that does not exist and encounter NULL pointer
dereference, which would likely lead to a crash. (CVE-2020-7062)

In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15 and 7.4.x below
7.4.3, when creating PHAR archive using PharData::buildFromIterator()
function, the files are added with default permissions (0666, or all
access) even if the original files on the filesystem were with more
restrictive permissions. This may result in files having more lax
permissions than intended when such archive is extracted.
(CVE-2020-7063)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1350.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php72' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"php72-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-bcmath-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-cli-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-common-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-dba-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-dbg-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-debuginfo-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-devel-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-embedded-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-enchant-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-fpm-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-gd-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-gmp-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-imap-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-intl-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-json-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-ldap-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-mbstring-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-mysqlnd-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-odbc-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-opcache-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pdo-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pdo-dblib-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pgsql-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-process-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pspell-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-recode-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-snmp-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-soap-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-tidy-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-xml-7.2.28-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-xmlrpc-7.2.28-1.21.amzn1")) flag++;

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
