#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-mod_php5-2238.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27148);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-5465");

  script_name(english:"openSUSE 10 Security Update : apache2-mod_php5 (apache2-mod_php5-2238)");
  script_summary(english:"Check for the apache2-mod_php5-2238 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security problems in the PHP scripting
language :

  - CVE-2006-5465: Various buffer overflows in
    htmlentities/htmlspecialchars internal routines could be
    used to crash the PHP interpreter or potentially execute
    code, depending on the PHP application used.

  - A missing open_basedir check inside chdir() function was
    added.

  - A tempnam() openbasedir bypass was fixed.

  - A possible buffer overflow in stream_socket_client()
    when using 'bindto' + IPv6 was fixed.

  - Do not build php5 with --enable-sigchld."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-mod_php5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-mysqli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/07");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"apache2-mod_php5-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-bcmath-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-curl-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-dba-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-devel-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-dom-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-exif-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-fastcgi-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-ftp-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-gd-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-iconv-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-imap-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-ldap-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mbstring-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mysql-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-mysqli-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pdo-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pear-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-pgsql-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-soap-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-wddx-5.1.2-29.22") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"php5-xmlrpc-5.1.2-29.22") ) flag++;

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