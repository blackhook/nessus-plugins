#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-985.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92982);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-5399", "CVE-2016-6128", "CVE-2016-6161", "CVE-2016-6207", "CVE-2016-6288", "CVE-2016-6289", "CVE-2016-6290", "CVE-2016-6291", "CVE-2016-6292", "CVE-2016-6295", "CVE-2016-6296", "CVE-2016-6297");

  script_name(english:"openSUSE Security Update : php5 (openSUSE-2016-985)");
  script_summary(english:"Check for the openSUSE-2016-985 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php5 fixes the following issues :

  - security update :

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

  - CVE-2016-6288: Buffer over-read in php_url_parse_ex
    [bsc#991433]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991437"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-firebird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mssql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-readline-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-suhosin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tidy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"apache2-mod_php5-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-mod_php5-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bcmath-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bcmath-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bz2-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-bz2-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-calendar-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-calendar-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ctype-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ctype-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-curl-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-curl-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dba-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dba-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-debugsource-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-devel-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dom-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-dom-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-enchant-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-enchant-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-exif-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-exif-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fastcgi-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fastcgi-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fileinfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fileinfo-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-firebird-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-firebird-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fpm-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-fpm-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ftp-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ftp-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gd-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gd-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gettext-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gettext-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gmp-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-gmp-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-iconv-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-iconv-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-imap-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-imap-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-intl-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-intl-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-json-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-json-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ldap-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-ldap-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mbstring-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mbstring-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mcrypt-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mcrypt-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mssql-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mssql-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mysql-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-mysql-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-odbc-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-odbc-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-opcache-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-opcache-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-openssl-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-openssl-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pcntl-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pcntl-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pdo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pdo-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pear-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pgsql-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pgsql-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-phar-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-phar-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-posix-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-posix-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pspell-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-pspell-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-readline-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-readline-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-shmop-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-shmop-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-snmp-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-snmp-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-soap-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-soap-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sockets-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sockets-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sqlite-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sqlite-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-suhosin-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-suhosin-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvmsg-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvmsg-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvsem-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvsem-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvshm-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-sysvshm-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tidy-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tidy-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tokenizer-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-tokenizer-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-wddx-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-wddx-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlreader-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlreader-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlrpc-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlrpc-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlwriter-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xmlwriter-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xsl-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-xsl-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zip-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zip-debuginfo-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zlib-5.6.1-72.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"php5-zlib-debuginfo-5.6.1-72.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_php5 / apache2-mod_php5-debuginfo / php5 / php5-bcmath / etc");
}
