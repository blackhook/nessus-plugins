#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3927-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155895);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/07");

  script_cve_id("CVE-2021-21707");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3927-1");
  script_xref(name:"IAVA", value:"2021-A-0566");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : php74 (SUSE-SU-2021:3927-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 host has packages installed that are affected by a vulnerability as referenced in
the SUSE-SU-2021:3927-1 advisory.

  - In PHP versions 7.3.x below 7.3.33, 7.4.x below 7.4.26 and 8.0.x below 8.0.13, certain XML parsing
    functions, like simplexml_load_file(), URL-decode the filename passed to them. If that filename contains
    URL-encoded NUL character, this may cause the function to interpret this as the end of the filename, thus
    interpreting the filename differently from what the user intended, which may lead it to reading a
    different file than intended. (CVE-2021-21707)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193041");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009842.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?268fa412");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21707");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21707");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php74");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sodium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php74-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'apache2-mod_php74-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'apache2-mod_php74-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'apache2-mod_php74-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'apache2-mod_php74-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-bcmath-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-bcmath-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-bcmath-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-bcmath-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-bz2-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-bz2-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-bz2-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-bz2-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-calendar-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-calendar-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-calendar-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-calendar-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ctype-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ctype-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ctype-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ctype-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-curl-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-curl-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-curl-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-curl-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-dba-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-dba-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-dba-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-dba-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-dom-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-dom-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-dom-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-dom-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-enchant-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-enchant-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-enchant-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-enchant-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-exif-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-exif-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-exif-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-exif-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fastcgi-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fastcgi-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fastcgi-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fastcgi-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fileinfo-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fileinfo-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fileinfo-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fileinfo-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fpm-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fpm-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fpm-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-fpm-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ftp-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ftp-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ftp-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ftp-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gd-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gd-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gd-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gd-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gettext-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gettext-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gettext-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gettext-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gmp-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gmp-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gmp-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-gmp-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-iconv-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-iconv-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-iconv-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-iconv-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-intl-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-intl-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-intl-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-intl-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-json-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-json-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-json-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-json-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ldap-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ldap-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ldap-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-ldap-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-mbstring-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-mbstring-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-mbstring-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-mbstring-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-mysql-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-mysql-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-mysql-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-mysql-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-odbc-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-odbc-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-odbc-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-odbc-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-opcache-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-opcache-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-opcache-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-opcache-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-openssl-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-openssl-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-openssl-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-openssl-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pcntl-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pcntl-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pcntl-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pcntl-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pdo-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pdo-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pdo-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pdo-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pgsql-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pgsql-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pgsql-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-pgsql-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-phar-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-phar-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-phar-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-phar-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-posix-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-posix-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-posix-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-posix-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-readline-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-readline-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-readline-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-readline-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-shmop-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-shmop-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-shmop-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-shmop-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-snmp-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-snmp-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-snmp-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-snmp-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-soap-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-soap-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-soap-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-soap-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sockets-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sockets-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sockets-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sockets-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sodium-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sodium-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sodium-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sodium-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sqlite-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sqlite-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sqlite-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sqlite-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvmsg-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvmsg-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvmsg-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvmsg-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvsem-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvsem-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvsem-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvsem-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvshm-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvshm-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvshm-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-sysvshm-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-tidy-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-tidy-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-tidy-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-tidy-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-tokenizer-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-tokenizer-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-tokenizer-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-tokenizer-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlreader-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlreader-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlreader-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlreader-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlrpc-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlrpc-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlrpc-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlrpc-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlwriter-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlwriter-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlwriter-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xmlwriter-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xsl-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xsl-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xsl-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-xsl-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-zip-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-zip-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-zip-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-zip-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-zlib-7.4.6-1.30.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-zlib-7.4.6-1.30.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-zlib-7.4.6-1.30.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-zlib-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-web-scripting-release-12-0'},
    {'reference':'php74-devel-7.4.6-1.30.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'php74-devel-7.4.6-1.30.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2-mod_php74 / php74 / php74-bcmath / php74-bz2 / php74-calendar / etc');
}
