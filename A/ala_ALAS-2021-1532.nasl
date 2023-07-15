#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1532.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153169);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/12");

  script_cve_id("CVE-2021-21704", "CVE-2021-21705");
  script_xref(name:"ALAS", value:"2021-1532");

  script_name(english:"Amazon Linux AMI : php73 (ALAS-2021-1532)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of php73 installed on the remote host is prior to 7.3.29-1.30. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2021-1532 advisory.

  - In PHP versions 7.3.x below 7.3.29, 7.4.x below 7.4.21 and 8.0.x below 8.0.8, when using URL validation
    functionality via filter_var() function with FILTER_VALIDATE_URL parameter, an URL with invalid password
    field can be accepted as valid. This can lead to the code incorrectly parsing the URL and potentially
    leading to other security implications - like contacting a wrong server or making a wrong access decision.
    (CVE-2021-21705)

  - In PHP versions 7.3.x below 7.3.29, 7.4.x below 7.4.21 and 8.0.x below 8.0.8, when using Firebird PDO
    driver extension, a malicious database server could cause crashes in various database functions, such as
    getAttribute(), execute(), fetch() and others by returning invalid response data that is not parsed
    correctly by the driver. This can result in crashes, denial of service or potentially memory corruption.
    (CVE-2021-21704)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1532.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21704");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-21705");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update php73' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/09");

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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'php73-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-bcmath-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-bcmath-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-cli-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-cli-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-common-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-common-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-dba-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-dba-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-dbg-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-dbg-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-debuginfo-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-debuginfo-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-devel-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-devel-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-embedded-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-embedded-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-enchant-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-enchant-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-fpm-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-fpm-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-gd-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-gd-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-gmp-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-gmp-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-imap-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-imap-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-intl-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-intl-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-json-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-json-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-ldap-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-ldap-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-mbstring-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-mbstring-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-mysqlnd-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-mysqlnd-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-odbc-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-odbc-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-opcache-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-opcache-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-pdo-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-pdo-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-pdo-dblib-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-pdo-dblib-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-pgsql-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-pgsql-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-process-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-process-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-pspell-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-pspell-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-recode-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-recode-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-snmp-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-snmp-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-soap-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-soap-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-tidy-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-tidy-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-xml-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-xml-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-xmlrpc-7.3.29-1.30.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php73-xmlrpc-7.3.29-1.30.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php73 / php73-bcmath / php73-cli / etc");
}