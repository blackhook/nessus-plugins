#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-mod_php5-3979.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27152);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-2727", "CVE-2007-2728", "CVE-2007-2748", "CVE-2007-3472", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478");

  script_name(english:"openSUSE 10 Security Update : apache2-mod_php5 (apache2-mod_php5-3979)");
  script_summary(english:"Check for the apache2-mod_php5-3979 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes multiple bugs in php :

  - predictable generaton of an initialization vector (IV)
    in the mcrypt extension

  - additional cookie attributes could be injected via a
    session id

  - specially crafted files could cause integer overflows in
    gd and leverage them to at least crash gd based
    applications

  - insufficient validation of parmeters in the substr_count
    function

  - predictable generaton of an initialization vector (IV)
    in the soap extension

CVE-2007-2727, CVE-2007-2748, CVE-2007-2728, CVE-2007-3472
CVE-2007-3475, CVE-2007-3476, CVE-2007-3477, CVE-2007-3478
CVE-2007-3799"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-mod_php5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(189, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mhash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"apache2-mod_php5-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-bcmath-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-bz2-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-calendar-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-ctype-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-curl-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-dba-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-dbase-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-devel-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-dom-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-exif-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-fastcgi-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-ftp-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-gd-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-gettext-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-gmp-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-hash-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-iconv-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-imap-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-json-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-ldap-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-mbstring-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-mcrypt-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-mhash-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-mysql-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-ncurses-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-odbc-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-openssl-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-pcntl-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-pdo-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-pear-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-pgsql-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-posix-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-pspell-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-shmop-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-snmp-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-soap-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-sockets-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-sqlite-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-suhosin-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-sysvmsg-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-sysvsem-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-sysvshm-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-tidy-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-tokenizer-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-wddx-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-xmlreader-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-xmlrpc-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-xmlwriter-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-xsl-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-zip-5.2.0-19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"php5-zlib-5.2.0-19") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php5");
}
