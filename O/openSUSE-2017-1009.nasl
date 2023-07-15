#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1009.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102965);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7436");

  script_name(english:"openSUSE Security Update : libzypp / zypper (openSUSE-2017-1009)");
  script_summary(english:"Check for the openSUSE-2017-1009 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Software Update Stack was updated to receive fixes and
enhancements.

libzypp :

  - Adapt to work with GnuPG 2.1.23. (bsc#1054088)

  - Support signing with subkeys. (bsc#1008325)

  - Enhance sort order for media.1/products. (bsc#1054671)

zypper :

  - Also show a gpg key's subkeys. (bsc#1008325)

  - Improve signature check callback messages. (bsc#1045735)

  - Add options to tune the GPG check settings.
    (bsc#1045735)

  - Adapt download callback to report and handle unsigned
    packages. (bsc#1038984, CVE-2017-7436)

  - Report missing/optional files as 'not found' rather than
    'error'. (bsc#1047785)

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055920"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libzypp / zypper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-aptitude");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-log");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/06");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libzypp-16.15.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzypp-debuginfo-16.15.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzypp-debugsource-16.15.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libzypp-devel-16.15.6-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-1.13.32-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-aptitude-1.13.32-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-debuginfo-1.13.32-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-debugsource-1.13.32-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"zypper-log-1.13.32-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libzypp / libzypp-debuginfo / libzypp-debugsource / libzypp-devel / etc");
}
