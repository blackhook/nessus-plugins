#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1200.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104236);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000254", "CVE-2017-1000257");

  script_name(english:"openSUSE Security Update : curl (openSUSE-2017-1200)");
  script_summary(english:"Check for the openSUSE-2017-1200 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for curl fixes the following issues :

Security issues fixed :

  - CVE-2017-1000254: FTP PWD response parser out of bounds
    read (bsc#1061876)

  - CVE-2017-1000257: IMAP FETCH response out of bounds read
    (bsc#1063824)

Bugs fixed :

  - Fixed error 'error:1408F10B:SSL routines' when
    connecting to ftps via proxy (bsc#1060653)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063824"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");
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

if ( rpm_check(release:"SUSE42.2", reference:"curl-7.37.0-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"curl-debuginfo-7.37.0-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"curl-debugsource-7.37.0-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcurl-devel-7.37.0-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcurl4-7.37.0-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libcurl4-debuginfo-7.37.0-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcurl-devel-32bit-7.37.0-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcurl4-32bit-7.37.0-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libcurl4-debuginfo-32bit-7.37.0-16.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"curl-7.37.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"curl-debuginfo-7.37.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"curl-debugsource-7.37.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcurl-devel-7.37.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcurl4-7.37.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcurl4-debuginfo-7.37.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libcurl-devel-32bit-7.37.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libcurl4-32bit-7.37.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libcurl4-debuginfo-32bit-7.37.0-23.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-debugsource / libcurl-devel-32bit / etc");
}
