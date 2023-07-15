#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1100.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103588);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-9300");

  script_name(english:"openSUSE Security Update : vlc (openSUSE-2017-1100)");
  script_summary(english:"Check for the openSUSE-2017-1100 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for vlc fixes several issues.

This security issue was fixed :

  - CVE-2017-9300: Heap corruption allowed remote attackers
    to cause a denial of service or possibly have
    unspecified other impact via a crafted FLAC file
    (bsc#1041907).

These non-security issues were fixed :

  - Stop depending on libkde4-devel: It's only used to find
    the install path for kde4, but configure falls back to
    the correct default for openSUSE anyway (boo#1057736).

  - Disable vnc access module"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057736"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vlc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-codec-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-codec-gstreamer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/02");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libvlc5-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvlc5-debuginfo-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvlccore8-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libvlccore8-debuginfo-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-codec-gstreamer-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-codec-gstreamer-debuginfo-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-debuginfo-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-debugsource-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-devel-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-lang-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-noX-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-noX-debuginfo-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-qt-2.2.6-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"vlc-qt-debuginfo-2.2.6-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvlc5 / libvlc5-debuginfo / libvlccore8 / libvlccore8-debuginfo / etc");
}
