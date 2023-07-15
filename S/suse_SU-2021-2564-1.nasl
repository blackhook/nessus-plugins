#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2564-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152162);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2021-21705");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2564-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : php72 (SUSE-SU-2021:2564-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 host has packages installed that are affected by a vulnerability as referenced in
the SUSE-SU-2021:2564-1 advisory.

  - Tenable.sc leverages third-party software to help provide underlying functionality. Multiple third-party
    components were found to contain vulnerabilities, and updated versions have been made available by the
    providers.  Out of caution, and in line with best practice, Tenable has upgraded the bundled components to
    address the potential impact of these issues. Tenable.sc 5.19.0 updates the following components:   1.
    Handlebars CVE-2019-19919 Severity: Critical   2. Underscore CVE-2021-23358 Severity: High   3. Apache FOP
    CVE-2017-5661 Severity: High   4. Bootstrap CVE-2019-8331, CVE-2018-20676, CVE-2018-20677, CVE-2018-14040,
    CVE-2018-14042, CVE-2016-10735  Highest Severity: Medium   5. PHP CVE-2019-11041, CVE-2019-11042,
    CVE-2019-11043, CVE-2019-11044, CVE-2019-11045, CVE-2019-11046, CVE-2019-11047, CVE-2019-11048,
    CVE-2019-11049, CVE-2019-11050, CVE-2020-7059, CVE-2020-7060, CVE-2020-7061, CVE-2020-7062, CVE-2020-7063,
    CVE-2020-7064, CVE-2020-7065, CVE-2020-7066, CVE-2020-7067, CVE-2020-7068, CVE-2020-7069, CVE-2020-7070,
    CVE-2020-7071, CVE-2021-21702, CVE-2021-21704, CVE-2021-21705 Highest Severity: Critical   6. sqlite
    CVE-2019-16168, CVE-2019-19645, CVE-2019-19646, CVE-2020-11655, CVE-2020-11656, CVE-2020-13434,
    CVE-2020-13435, CVE-2020-13630, CVE-2020-13631, CVE-2020-13632, CVE-2020-15358  Highest Severity: Critical
    7. SimpleSAMLPHP CVE-2020-11022 Severity: Medium  Tenable has released Tenable.sc 5.19.0 to address these
    issues. The installation files can be obtained from the Tenable Downloads Portal
    (https://www.tenable.com/downloads/tenable-sc). (CVE-2021-21705)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188037");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-July/009232.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a646d8f7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21705");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pear-Archive_Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sodium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + sp);
if (os_ver == "SLES12" && (! preg(pattern:"^(0|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/3/4/5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'apache2-mod_php72-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'apache2-mod_php72-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'apache2-mod_php72-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'apache2-mod_php72-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-bcmath-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-bcmath-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-bcmath-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-bcmath-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-bz2-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-bz2-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-bz2-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-bz2-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-calendar-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-calendar-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-calendar-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-calendar-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ctype-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ctype-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ctype-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ctype-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-curl-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-curl-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-curl-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-curl-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-dba-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-dba-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-dba-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-dba-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-dom-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-dom-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-dom-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-dom-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-enchant-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-enchant-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-enchant-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-enchant-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-exif-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-exif-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-exif-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-exif-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fastcgi-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fastcgi-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fastcgi-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fastcgi-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fileinfo-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fileinfo-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fileinfo-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fileinfo-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fpm-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fpm-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fpm-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-fpm-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ftp-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ftp-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ftp-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ftp-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gd-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gd-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gd-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gd-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gettext-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gettext-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gettext-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gettext-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gmp-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gmp-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gmp-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-gmp-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-iconv-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-iconv-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-iconv-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-iconv-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-imap-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-imap-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-imap-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-imap-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-intl-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-intl-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-intl-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-intl-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-json-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-json-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-json-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-json-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ldap-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ldap-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ldap-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-ldap-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-mbstring-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-mbstring-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-mbstring-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-mbstring-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-mysql-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-mysql-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-mysql-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-mysql-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-odbc-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-odbc-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-odbc-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-odbc-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-opcache-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-opcache-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-opcache-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-opcache-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-openssl-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-openssl-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-openssl-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-openssl-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pcntl-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pcntl-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pcntl-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pcntl-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pdo-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pdo-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pdo-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pdo-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pear-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pear-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pear-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pear-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pgsql-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pgsql-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pgsql-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pgsql-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-phar-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-phar-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-phar-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-phar-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-posix-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-posix-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-posix-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-posix-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pspell-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pspell-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pspell-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-pspell-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-readline-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-readline-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-readline-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-readline-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-shmop-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-shmop-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-shmop-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-shmop-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-snmp-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-snmp-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-snmp-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-snmp-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-soap-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-soap-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-soap-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-soap-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sockets-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sockets-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sockets-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sockets-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sodium-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sodium-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sodium-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sodium-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sqlite-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sqlite-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sqlite-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sqlite-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvmsg-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvmsg-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvmsg-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvmsg-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvsem-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvsem-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvsem-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvsem-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvshm-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvshm-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvshm-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-sysvshm-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-tidy-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-tidy-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-tidy-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-tidy-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-tokenizer-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-tokenizer-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-tokenizer-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-tokenizer-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-wddx-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-wddx-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-wddx-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-wddx-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlreader-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlreader-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlreader-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlreader-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlrpc-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlrpc-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlrpc-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlrpc-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlwriter-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlwriter-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlwriter-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xmlwriter-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xsl-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xsl-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xsl-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-xsl-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-zip-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-zip-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-zip-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-zip-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-zlib-7.2.5-1.63.2', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-zlib-7.2.5-1.63.2', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-zlib-7.2.5-1.63.2', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-zlib-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php72-devel-7.2.5-1.63.2', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'php72-devel-7.2.5-1.63.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2-mod_php72 / php72 / php72-bcmath / php72-bz2 / php72-calendar / etc');
}
