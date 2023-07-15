#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-081.
##

include('compat.inc');

if (description)
{
  script_id(173063);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2022-31627",
    "CVE-2022-31628",
    "CVE-2022-31629",
    "CVE-2022-31630",
    "CVE-2022-31631",
    "CVE-2022-37454"
  );

  script_name(english:"Amazon Linux 2023 : php8.1, php8.1-bcmath, php8.1-cli (ALAS2023-2023-081)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-081 advisory.

  - In PHP versions 8.1.x below 8.1.8, when fileinfo functions, such as finfo_buffer, due to incorrect patch
    applied to the third party code from libmagic, incorrect function may be used to free allocated memory,
    which may lead to heap corruption. (CVE-2022-31627)

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the phar uncompressor code would recursively uncompress
    quines gzip files, resulting in an infinite loop. (CVE-2022-31628)

  - In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the vulnerability enables network and same-site
    attackers to set a standard insecure cookie in the victim's browser which is treated as a `__Host-` or
    `__Secure-` cookie by PHP applications. (CVE-2022-31629)

  - In PHP versions prior to 7.4.33, 8.0.25 and 8.2.12, when using imageloadfont() function in gd extension,
    it is possible to supply a specially crafted font file, such as if the loaded font is used with
    imagechar() function, the read outside allocated buffer will be used. This can lead to crashes or
    disclosure of confidential information. (CVE-2022-31630)

  - The Keccak XKCP SHA-3 reference implementation before fdc6fef has an integer overflow and resultant buffer
    overflow that allows attackers to execute arbitrary code or eliminate expected cryptographic properties.
    This occurs in the sponge function interface. (CVE-2022-37454)

  - php: PDO::quote() may return unquoted string due to an integer overflow (CVE-2022-31631)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-081.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31627.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31628.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31629.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31630.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31631.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-37454.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update php8.1 --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37454");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-cli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-dbg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-embedded-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-ffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-mysqlnd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-process-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-tidy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php8.1-xml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'php8.1-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-bcmath-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-bcmath-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-bcmath-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-bcmath-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-bcmath-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-bcmath-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-cli-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-cli-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-cli-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-cli-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-cli-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-cli-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-common-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-common-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-common-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-common-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-common-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-common-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dba-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dba-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dba-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dba-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dba-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dba-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dbg-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dbg-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dbg-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dbg-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dbg-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-dbg-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-debugsource-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-debugsource-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-debugsource-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-devel-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-devel-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-devel-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-embedded-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-embedded-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-embedded-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-embedded-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-embedded-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-embedded-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-enchant-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-enchant-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-enchant-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-enchant-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-enchant-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-enchant-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ffi-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ffi-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ffi-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ffi-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ffi-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ffi-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-fpm-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-fpm-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-fpm-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-fpm-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-fpm-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-fpm-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gd-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gd-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gd-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gd-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gd-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gd-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gmp-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gmp-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gmp-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gmp-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gmp-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-gmp-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-intl-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-intl-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-intl-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-intl-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-intl-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-intl-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ldap-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ldap-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ldap-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ldap-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ldap-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-ldap-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mbstring-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mbstring-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mbstring-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mbstring-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mbstring-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mbstring-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mysqlnd-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mysqlnd-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mysqlnd-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mysqlnd-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mysqlnd-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-mysqlnd-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-odbc-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-odbc-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-odbc-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-odbc-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-odbc-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-odbc-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-opcache-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-opcache-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-opcache-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-opcache-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-opcache-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-opcache-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pdo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pdo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pdo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pdo-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pdo-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pdo-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pgsql-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pgsql-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pgsql-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pgsql-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pgsql-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-pgsql-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-process-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-process-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-process-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-process-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-process-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-process-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-soap-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-soap-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-soap-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-soap-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-soap-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-soap-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-tidy-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-tidy-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-tidy-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-tidy-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-tidy-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-tidy-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-xml-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-xml-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-xml-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-xml-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-xml-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php8.1-xml-debuginfo-8.1.14-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php8.1 / php8.1-bcmath / php8.1-bcmath-debuginfo / etc");
}