#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-939.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87618);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-6792");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-2015-939)");
  script_summary(english:"Check for the openSUSE-2015-939 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 47.0.2525.106 to fix security issues.

Vulnerabilities were fixed under the following collective identifier :

  - CVE-2015-6792: Fixes from internal audits and fuzzing.
    [boo#959458]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959458"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-47.0.2526.106-119.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-47.0.2526.106-119.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-47.0.2526.106-119.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-47.0.2526.106-119.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-47.0.2526.106-119.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-47.0.2526.106-119.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-47.0.2526.106-119.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-47.0.2526.106-119.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-47.0.2526.106-119.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-47.0.2526.106-64.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-47.0.2526.106-64.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-47.0.2526.106-64.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-47.0.2526.106-64.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debugsource-47.0.2526.106-64.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-47.0.2526.106-64.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-47.0.2526.106-64.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-47.0.2526.106-64.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-47.0.2526.106-64.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-47.0.2526.106-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromedriver-debuginfo-47.0.2526.106-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-47.0.2526.106-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debuginfo-47.0.2526.106-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-debugsource-47.0.2526.106-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-gnome-47.0.2526.106-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-desktop-kde-47.0.2526.106-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-47.0.2526.106-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"chromium-ffmpegsumo-debuginfo-47.0.2526.106-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
