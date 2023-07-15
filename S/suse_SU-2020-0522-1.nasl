#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0522-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134199);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-11041",
    "CVE-2019-11042",
    "CVE-2019-11043",
    "CVE-2019-11045",
    "CVE-2019-11046",
    "CVE-2019-11047",
    "CVE-2019-11050",
    "CVE-2020-7059",
    "CVE-2020-7060"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"SUSE SLES12 Security Update : php5 (SUSE-SU-2020:0522-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for php5 fixes the following issues :

Security issues fixed :

CVE-2019-11041: Fixed heap buffer over-read in exif_scan_thumbnail()
(bsc#1146360).

CVE-2019-11042: Fixed heap buffer over-read in
exif_process_user_comment() (bsc#1145095).

CVE-2019-11043: Fixed possible remote code execution via env_path_info
underflow in fpm_main.c (bsc#1154999).

CVE-2019-11045: Fixed an issue with the PHP DirectoryIterator class
that accepts filenames with embedded \0 bytes (bsc#1159923).

CVE-2019-11046: Fixed an out-of-bounds read in bc_shift_addsub
(bsc#1159924).

CVE-2019-11047: Fixed an information disclosure in exif_read_data
(bsc#1159922).

CVE-2019-11050: Fixed a buffer over-read in the EXIF extension
(bsc#1159927).

CVE-2020-7059: Fixed an out-of-bounds read in php_strip_tags_ex
(bsc#1162629).

CVE-2020-7060: Fixed a global buffer-overflow in
mbfl_filt_conv_big5_wchar (bsc#1162632).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1145095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1154999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1159927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1161982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1162632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11041/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11042/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11043/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11045/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11046/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11047/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11050/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7059/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7060/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200522-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e9a53cf");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2020-522=1

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2020-522=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-pspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-suhosin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php5-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php5-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php5-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bcmath-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bcmath-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bz2-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bz2-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-calendar-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-calendar-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ctype-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ctype-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-curl-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-curl-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dba-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dba-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-debugsource-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dom-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dom-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-enchant-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-enchant-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-exif-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-exif-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fastcgi-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fastcgi-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fileinfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fileinfo-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fpm-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fpm-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ftp-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ftp-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gd-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gd-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gettext-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gettext-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gmp-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gmp-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-iconv-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-iconv-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-imap-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-imap-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-intl-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-intl-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-json-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-json-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ldap-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ldap-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mbstring-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mbstring-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mcrypt-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mcrypt-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mysql-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mysql-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-odbc-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-odbc-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-opcache-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-opcache-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-openssl-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-openssl-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pcntl-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pcntl-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pdo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pdo-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pgsql-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pgsql-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-phar-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-phar-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-posix-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-posix-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pspell-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pspell-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-shmop-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-shmop-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-snmp-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-snmp-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-soap-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-soap-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sockets-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sockets-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sqlite-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sqlite-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-suhosin-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-suhosin-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvmsg-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvmsg-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvsem-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvsem-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvshm-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvshm-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-tokenizer-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-tokenizer-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-wddx-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-wddx-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlreader-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlreader-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlrpc-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlrpc-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlwriter-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlwriter-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xsl-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xsl-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zip-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zip-debuginfo-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zlib-5.5.14-109.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zlib-debuginfo-5.5.14-109.68.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php5");
}
