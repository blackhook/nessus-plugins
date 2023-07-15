#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1351.
#

include("compat.inc");

if (description)
{
  script_id(134573);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/18");

  script_cve_id("CVE-2020-7061", "CVE-2020-7062", "CVE-2020-7063");
  script_xref(name:"ALAS", value:"2020-1351");

  script_name(english:"Amazon Linux AMI : php73 (ALAS-2020-1351)");
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
    value:"https://alas.aws.amazon.com/ALAS-2020-1351.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php73' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
if (rpm_check(release:"ALA", reference:"php73-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-bcmath-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-cli-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-common-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-dba-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-dbg-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-debuginfo-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-devel-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-embedded-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-enchant-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-fpm-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-gd-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-gmp-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-imap-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-intl-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-json-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-ldap-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-mbstring-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-mysqlnd-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-odbc-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-opcache-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pdo-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pdo-dblib-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pgsql-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-process-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pspell-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-recode-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-snmp-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-soap-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-tidy-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-xml-7.3.15-1.24.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-xmlrpc-7.3.15-1.24.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php73 / php73-bcmath / php73-cli / php73-common / php73-dba / etc");
}
