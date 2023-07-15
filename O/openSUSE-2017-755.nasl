#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-755.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101190);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-9604");

  script_name(english:"openSUSE Security Update : kdepim4 (openSUSE-2017-755)");
  script_summary(english:"Check for the openSUSE-2017-755 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kdepim4 fixes the following issues :

  - CVE-2017-9604: The kmail 'send later' function does not
    have 'sign/encryption' action ensured. (boo#1044210)

The package kdepim-addons was updated to conflict with 4.x based
akonadi package to prevent file conflicts. (boo#1045936)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045936"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdepim4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:akonadi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:akonadi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:akregator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:akregator-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kaddressbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kaddressbook-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kalarm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kalarm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim-addons-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdepim4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:knode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:knode-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:knotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:knotes-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kontact");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kontact-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:korganizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:korganizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ktimetracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ktimetracker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ktnef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ktnef-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdepim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdepim4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/03");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"akonadi-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"akonadi-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"akregator-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"akregator-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kaddressbook-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kaddressbook-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kalarm-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kalarm-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdepim-addons-16.08.2-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdepim-addons-debuginfo-16.08.2-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdepim-addons-debugsource-16.08.2-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdepim4-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdepim4-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdepim4-debugsource-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kmail-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kmail-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"knode-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"knode-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"knotes-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"knotes-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kontact-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kontact-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"korganizer-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"korganizer-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ktimetracker-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ktimetracker-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ktnef-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ktnef-debuginfo-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdepim4-4.14.10-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdepim4-debuginfo-4.14.10-6.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdepim-addons / kdepim-addons-debuginfo / kdepim-addons-debugsource / etc");
}
