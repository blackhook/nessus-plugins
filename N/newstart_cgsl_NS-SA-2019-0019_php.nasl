#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0019. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127174);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-10167", "CVE-2016-10168", "CVE-2017-7890");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : php Multiple Vulnerabilities (NS-SA-2019-0019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has php packages installed that are affected by
multiple vulnerabilities:

  - An integer overflow flaw, leading to a heap-based buffer
    overflow was found in the way libgd read some specially-
    crafted gd2 files. A remote attacker could use this flaw
    to crash an application compiled with libgd or in
    certain cases execute arbitrary code with the privileges
    of the user running that application. (CVE-2016-10168)

  - A null pointer dereference flaw was found in libgd. An
    attacker could use a specially-crafted .gd2 file to
    cause an application linked with libgd to crash, leading
    to denial of service. (CVE-2016-10167)

  - A data leak was found in gdImageCreateFromGifCtx() in GD
    Graphics Library used in PHP before 5.6.31 and 7.1.7. An
    attacker could craft a malicious GIF image and read up
    to 762 bytes from stack. (CVE-2017-7890)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0019");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL php packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10168");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "php-5.4.16-43.el7_4.1",
    "php-bcmath-5.4.16-43.el7_4.1",
    "php-cli-5.4.16-43.el7_4.1",
    "php-common-5.4.16-43.el7_4.1",
    "php-dba-5.4.16-43.el7_4.1",
    "php-debuginfo-5.4.16-43.el7_4.1",
    "php-devel-5.4.16-43.el7_4.1",
    "php-embedded-5.4.16-43.el7_4.1",
    "php-enchant-5.4.16-43.el7_4.1",
    "php-fpm-5.4.16-43.el7_4.1",
    "php-gd-5.4.16-43.el7_4.1",
    "php-intl-5.4.16-43.el7_4.1",
    "php-ldap-5.4.16-43.el7_4.1",
    "php-mbstring-5.4.16-43.el7_4.1",
    "php-mysql-5.4.16-43.el7_4.1",
    "php-mysqlnd-5.4.16-43.el7_4.1",
    "php-odbc-5.4.16-43.el7_4.1",
    "php-pdo-5.4.16-43.el7_4.1",
    "php-pgsql-5.4.16-43.el7_4.1",
    "php-process-5.4.16-43.el7_4.1",
    "php-pspell-5.4.16-43.el7_4.1",
    "php-recode-5.4.16-43.el7_4.1",
    "php-snmp-5.4.16-43.el7_4.1",
    "php-soap-5.4.16-43.el7_4.1",
    "php-xml-5.4.16-43.el7_4.1",
    "php-xmlrpc-5.4.16-43.el7_4.1"
  ],
  "CGSL MAIN 5.04": [
    "php-5.4.16-43.el7_4.1",
    "php-bcmath-5.4.16-43.el7_4.1",
    "php-cli-5.4.16-43.el7_4.1",
    "php-common-5.4.16-43.el7_4.1",
    "php-dba-5.4.16-43.el7_4.1",
    "php-debuginfo-5.4.16-43.el7_4.1",
    "php-devel-5.4.16-43.el7_4.1",
    "php-embedded-5.4.16-43.el7_4.1",
    "php-enchant-5.4.16-43.el7_4.1",
    "php-fpm-5.4.16-43.el7_4.1",
    "php-gd-5.4.16-43.el7_4.1",
    "php-intl-5.4.16-43.el7_4.1",
    "php-ldap-5.4.16-43.el7_4.1",
    "php-mbstring-5.4.16-43.el7_4.1",
    "php-mysql-5.4.16-43.el7_4.1",
    "php-mysqlnd-5.4.16-43.el7_4.1",
    "php-odbc-5.4.16-43.el7_4.1",
    "php-pdo-5.4.16-43.el7_4.1",
    "php-pgsql-5.4.16-43.el7_4.1",
    "php-process-5.4.16-43.el7_4.1",
    "php-pspell-5.4.16-43.el7_4.1",
    "php-recode-5.4.16-43.el7_4.1",
    "php-snmp-5.4.16-43.el7_4.1",
    "php-soap-5.4.16-43.el7_4.1",
    "php-xml-5.4.16-43.el7_4.1",
    "php-xmlrpc-5.4.16-43.el7_4.1"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
