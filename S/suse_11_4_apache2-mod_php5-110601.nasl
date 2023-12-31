#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-mod_php5-4647.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75790);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-0421", "CVE-2011-1092", "CVE-2011-1148", "CVE-2011-1464", "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1470", "CVE-2011-1471", "CVE-2011-1938");

  script_name(english:"openSUSE Security Update : apache2-mod_php5 (openSUSE-SU-2011:0645-1)");
  script_summary(english:"Check for the apache2-mod_php5-4647 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This php5 update fixes :

  - CVE-2011-0421: CVSS v2 Base Score: 2.6
    (AV:N/AC:H/Au:N/C:N/I:N/A:P): Input Validation (CWE-20)

  - CVE-2011-1092: CVSS v2 Base Score: 5.1
    (AV:N/AC:H/Au:N/C:P/I:P/A:P): Numeric Errors (CWE-189)

  - CVE-2011-1148: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:N/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2011-1464: CVSS v2 Base Score: 2.1
    (AV:L/AC:L/Au:N/C:N/I:N/A:P): Buffer Errors (CWE-119)

  - CVE-2011-1467: CVSS v2 Base Score: 5.0
    (AV:N/AC:L/Au:N/C:N/I:N/A:P)

  - CVE-2011-1468: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:N/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2011-1469: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:N/A:P)

  - CVE-2011-1470: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:N/A:P): Input Validation (CWE-20)

  - CVE-2011-1471: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:N/A:P): Numeric Errors (CWE-189)

  - CVE-2011-1938: CVSS v2 Base Score: 2.6
    (AV:N/AC:H/Au:N/C:N/I:N/A:P)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=677782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=679278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=695689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-06/msg00032.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-mod_php5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-hash-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-odbc-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"apache2-mod_php5-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-mod_php5-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-bcmath-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-bcmath-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-bz2-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-bz2-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-calendar-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-calendar-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-ctype-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-ctype-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-curl-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-curl-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-dba-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-dba-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-debugsource-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-devel-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-dom-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-dom-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-enchant-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-enchant-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-exif-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-exif-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-fastcgi-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-fastcgi-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-fileinfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-fileinfo-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-fpm-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-fpm-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-ftp-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-ftp-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-gd-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-gd-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-gettext-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-gettext-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-gmp-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-gmp-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-hash-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-hash-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-iconv-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-iconv-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-imap-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-imap-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-intl-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-intl-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-json-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-json-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-ldap-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-ldap-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-mbstring-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-mbstring-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-mcrypt-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-mcrypt-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-mysql-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-mysql-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-odbc-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-odbc-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-openssl-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-openssl-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-pcntl-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-pcntl-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-pdo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-pdo-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-pear-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-pgsql-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-pgsql-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-phar-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-phar-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-posix-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-posix-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-pspell-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-pspell-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-readline-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-readline-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-shmop-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-shmop-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-snmp-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-snmp-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-soap-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-soap-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sockets-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sockets-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sqlite-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sqlite-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-suhosin-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-suhosin-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sysvmsg-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sysvmsg-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sysvsem-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sysvsem-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sysvshm-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-sysvshm-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-tidy-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-tidy-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-tokenizer-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-tokenizer-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-wddx-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-wddx-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-xmlreader-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-xmlreader-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-xmlrpc-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-xmlrpc-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-xmlwriter-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-xmlwriter-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-xsl-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-xsl-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-zip-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-zip-debuginfo-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-zlib-5.3.5-5.14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"php5-zlib-debuginfo-5.3.5-5.14.1") ) flag++;

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
