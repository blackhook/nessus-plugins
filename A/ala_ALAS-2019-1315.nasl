#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1315.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(130471);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-11043");
  script_xref(name:"ALAS", value:"2019-1315");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"Amazon Linux AMI : php71 / php72, php73, php56 (ALAS-2019-1315)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below
7.3.11 in certain configurations of FPM setup it is possible to cause
FPM module to write past allocated buffers into the space reserved for
FCGI protocol data, thus opening the possibility of remote code
execution.(CVE-2019-11043)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1315.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Run 'yum update php71' to update your system.

Run 'yum update php72' to update your system.

Run 'yum update php73' to update your system.

Run 'yum update php56' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11043");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"php56-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-bcmath-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-cli-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-common-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dba-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dbg-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-debuginfo-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-devel-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-embedded-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-enchant-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-fpm-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gd-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gmp-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-imap-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-intl-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-ldap-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mbstring-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mcrypt-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mssql-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mysqlnd-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-odbc-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-opcache-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pdo-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pgsql-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-process-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pspell-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-recode-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-snmp-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-soap-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-tidy-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xml-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xmlrpc-5.6.40-1.143.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-bcmath-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-cli-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-common-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-dba-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-dbg-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-debuginfo-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-devel-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-embedded-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-enchant-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-fpm-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-gd-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-gmp-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-imap-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-intl-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-json-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-ldap-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-mbstring-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-mcrypt-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-mysqlnd-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-odbc-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-opcache-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pdo-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pdo-dblib-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pgsql-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-process-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pspell-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-recode-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-snmp-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-soap-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-tidy-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-xml-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-xmlrpc-7.1.33-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-bcmath-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-cli-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-common-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-dba-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-dbg-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-debuginfo-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-devel-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-embedded-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-enchant-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-fpm-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-gd-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-gmp-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-imap-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-intl-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-json-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-ldap-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-mbstring-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-mysqlnd-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-odbc-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-opcache-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pdo-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pdo-dblib-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pgsql-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-process-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pspell-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-recode-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-snmp-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-soap-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-tidy-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-xml-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-xmlrpc-7.2.24-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-bcmath-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-cli-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-common-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-dba-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-dbg-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-debuginfo-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-devel-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-embedded-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-enchant-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-fpm-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-gd-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-gmp-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-imap-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-intl-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-json-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-ldap-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-mbstring-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-mysqlnd-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-odbc-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-opcache-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pdo-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pdo-dblib-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pgsql-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-process-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-pspell-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-recode-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-snmp-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-soap-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-tidy-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-xml-7.3.11-1.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php73-xmlrpc-7.3.11-1.21.amzn1")) flag++;

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
