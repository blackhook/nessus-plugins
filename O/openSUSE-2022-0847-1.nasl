#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0847-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159039);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/17");

  script_cve_id("CVE-2021-21708");

  script_name(english:"openSUSE 15 Security Update : php7 (openSUSE-SU-2022:0847-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2022:0847-1 advisory.

  - In PHP versions 7.4.x below 7.4.28, 8.0.x below 8.0.16, and 8.1.x below 8.1.3, when using filter functions
    with FILTER_VALIDATE_FLOAT filter and min/max limits, if the filter fails, there is a possibility to
    trigger use of allocated memory after free, which can result it crashes, and potentially in overwrite of
    other memory chunks and RCE. This issue affects: code that uses FILTER_VALIDATE_FLOAT with min/max limits.
    (CVE-2021-21708)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196252");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KW6LMSP5SUI42MJ5THSQEU35CZFOBTL3/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8821f405");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21708");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sodium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'apache2-mod_php7-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-bcmath-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-bz2-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-calendar-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-ctype-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-curl-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-dba-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-devel-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-dom-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-embed-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-enchant-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-exif-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-fastcgi-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-fileinfo-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-firebird-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-fpm-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-ftp-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-gd-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-gettext-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-gmp-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-iconv-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-intl-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-json-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-ldap-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-mbstring-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-mysql-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-odbc-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-opcache-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-openssl-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-pcntl-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-pdo-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-pgsql-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-phar-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-posix-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-readline-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-shmop-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-snmp-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-soap-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-sockets-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-sodium-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-sqlite-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-sysvmsg-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-sysvsem-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-sysvshm-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-test-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-tidy-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-tokenizer-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-xmlreader-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-xmlrpc-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-xmlwriter-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-xsl-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-zip-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'php7-zlib-7.4.6-3.35.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2-mod_php7 / php7 / php7-bcmath / php7-bz2 / php7-calendar / etc');
}
