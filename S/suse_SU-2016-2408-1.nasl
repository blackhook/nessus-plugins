#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2408-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119979);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id(
    "CVE-2014-3587",
    "CVE-2016-3587",
    "CVE-2016-5399",
    "CVE-2016-6128",
    "CVE-2016-6161",
    "CVE-2016-6207",
    "CVE-2016-6288",
    "CVE-2016-6289",
    "CVE-2016-6290",
    "CVE-2016-6291",
    "CVE-2016-6292",
    "CVE-2016-6295",
    "CVE-2016-6296",
    "CVE-2016-6297",
    "CVE-2016-7124",
    "CVE-2016-7125",
    "CVE-2016-7126",
    "CVE-2016-7127",
    "CVE-2016-7128",
    "CVE-2016-7129",
    "CVE-2016-7130",
    "CVE-2016-7131",
    "CVE-2016-7132",
    "CVE-2016-7134"
  );
  script_bugtraq_id(69325);

  script_name(english:"SUSE SLES12 Security Update : php5 (SUSE-SU-2016:2408-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for php5 fixes the following security issues :

  - CVE-2016-6128: Invalid color index not properly handled
    [bsc#987580]

  - CVE-2016-6161: global out of bounds read when encoding
    gif from malformed input withgd2togif [bsc#988032]

  - CVE-2016-6292: NULL pointer dereference in
    exif_process_user_comment [bsc#991422]

  - CVE-2016-6295: Use after free in SNMP with GC and
    unserialize() [bsc#991424]

  - CVE-2016-6297: Stack-based buffer overflow vulnerability
    in php_stream_zip_opener [bsc#991426]

  - CVE-2016-6291: Out-of-bounds access in
    exif_process_IFD_in_MAKERNOTE [bsc#991427]

  - CVE-2016-6289: Integer overflow leads to buffer overflow
    in virtual_file_ex [bsc#991428]

  - CVE-2016-6290: Use after free in unserialize() with
    Unexpected Session Deserialization [bsc#991429]

  - CVE-2016-5399: Improper error handling in bzread()
    [bsc#991430]

  - CVE-2016-6296: Heap buffer overflow vulnerability in
    simplestring_addn in simplestring.c [bsc#991437]

  - CVE-2016-6207: Integer overflow error within
    _gdContributionsAlloc() [bsc#991434]

  - CVE-2014-3587: Integer overflow in the
    cdf_read_property_info affecting SLES11 SP3 [bsc#987530]

  - CVE-2016-6288: Buffer over-read in php_url_parse_ex
    [bsc#991433]

  - CVE-2016-7124: Create an Unexpected Object and Don't
    Invoke __wakeup() in Deserialization

  - CVE-2016-7125: PHP Session Data Injection Vulnerability

  - CVE-2016-7126: select_colors write out-of-bounds

  - CVE-2016-7127: imagegammacorrect allowed arbitrary write
    access

  - CVE-2016-7128: Memory Leakage In
    exif_process_IFD_in_TIFF

  - CVE-2016-7129: wddx_deserialize allowed illegal memory
    access

  - CVE-2016-7130: wddx_deserialize null dereference

  - CVE-2016-7131: wddx_deserialize null dereference with
    invalid xml

  - CVE-2016-7132: wddx_deserialize null dereference in
    php_wddx_pop_element

  - CVE-2016-7134: Heap overflow in the function curl_escape

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=987530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=987580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=988032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=991437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997257");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-3587/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-3587/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-5399/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6128/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6161/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6207/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6288/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6289/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6290/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6291/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6292/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6295/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6296/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6297/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7124/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7125/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7126/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7127/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7128/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7129/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7130/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7131/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7132/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-7134/");
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162408-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cb9502a");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1403=1

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2016-1403=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3587");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-7134");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");

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

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php5-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"apache2-mod_php5-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bcmath-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bcmath-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bz2-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-bz2-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-calendar-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-calendar-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ctype-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ctype-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-curl-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-curl-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dba-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dba-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-debugsource-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dom-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-dom-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-enchant-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-enchant-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-exif-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-exif-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fastcgi-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fastcgi-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fileinfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fileinfo-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fpm-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-fpm-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ftp-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ftp-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gd-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gd-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gettext-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gettext-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gmp-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-gmp-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-iconv-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-iconv-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-imap-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-imap-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-intl-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-intl-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-json-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-json-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ldap-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-ldap-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mbstring-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mbstring-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mcrypt-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mcrypt-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mysql-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-mysql-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-odbc-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-odbc-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-opcache-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-opcache-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-openssl-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-openssl-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pcntl-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pcntl-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pdo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pdo-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pgsql-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pgsql-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-phar-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-phar-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-posix-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-posix-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pspell-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-pspell-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-shmop-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-shmop-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-snmp-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-snmp-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-soap-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-soap-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sockets-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sockets-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sqlite-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sqlite-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-suhosin-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-suhosin-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvmsg-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvmsg-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvsem-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvsem-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvshm-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-sysvshm-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-tokenizer-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-tokenizer-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-wddx-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-wddx-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlreader-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlreader-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlrpc-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlrpc-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlwriter-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xmlwriter-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xsl-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-xsl-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zip-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zip-debuginfo-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zlib-5.5.14-73.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"php5-zlib-debuginfo-5.5.14-73.1")) flag++;


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
