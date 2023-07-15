#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-104.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106523);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7659", "CVE-2017-9789");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2018-104)");
  script_summary(english:"Check for the openSUSE-2018-104 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for apache2 fixes several issues.

These security issues were fixed :

  - CVE-2017-9789: When under stress (closing many
    connections) the HTTP/2 handling code would sometimes
    access memory after it has been freed, resulting in
    potentially erratic behaviour (bsc#1048575).

  - CVE-2017-7659: A maliciously constructed HTTP/2 request
    could cause mod_http2 to dereference a NULL pointer and
    crash the server process (bsc#1045160).

These non-security issues were fixed :

  - Use the full path to a2enmod and a2dismod in the
    apache-22-24-upgrade script (bsc#1042037)

  - Fall back to 'localhost' as hostname in gensslcert
    (bsc#1057406)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057406"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"apache2-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-debuginfo-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-debugsource-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-devel-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-event-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-event-debuginfo-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-example-pages-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-prefork-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-prefork-debuginfo-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-utils-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-utils-debuginfo-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-worker-2.4.23-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-worker-debuginfo-2.4.23-19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
