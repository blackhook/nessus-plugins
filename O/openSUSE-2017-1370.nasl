#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1370.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105265);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12618");

  script_name(english:"openSUSE Security Update : libapr-util1 (openSUSE-2017-1370)");
  script_summary(english:"Check for the openSUSE-2017-1370 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libapr-util1 fixes the following issues :

Security issue fixed :

  - CVE-2017-12618: DoS via crafted SDBM database files in
    apr_sdbm*() functions (bsc#1064990)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064990"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libapr-util1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-dbd-sqlite3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapr-util1-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-dbd-mysql-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-dbd-mysql-debuginfo-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-dbd-pgsql-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-dbd-pgsql-debuginfo-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-dbd-sqlite3-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-dbd-sqlite3-debuginfo-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-debuginfo-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-debugsource-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libapr-util1-devel-1.5.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-1.5.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-dbd-mysql-1.5.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-dbd-mysql-debuginfo-1.5.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-dbd-pgsql-1.5.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-dbd-pgsql-debuginfo-1.5.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-dbd-sqlite3-1.5.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-dbd-sqlite3-debuginfo-1.5.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-debuginfo-1.5.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-debugsource-1.5.3-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libapr-util1-devel-1.5.3-8.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapr-util1 / libapr-util1-dbd-mysql / etc");
}
