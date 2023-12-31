#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2014/08/08.
#

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014--1.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76934);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/20  0:18:55");

  script_cve_id("CVE-2014-3970");

  script_name(english:"openSUSE Security Update : openSUSE-2014- (openSUSE-2014--1)");
  script_summary(english:"Check for the openSUSE-2014--1 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"&#9;This update fixes the following security issue: &#9;(bnc#881524)
CVE-2014-3970 - Denial of service in module-rtp-recv"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openSUSE-2014- packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse-mainloop-glib0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse-mainloop-glib0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse-mainloop-glib0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse-mainloop-glib0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpulse0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-gdm-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-bluetooth-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-gconf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-jack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-lirc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-module-zeroconf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-system-wide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pulseaudio-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");



include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libpulse-devel-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpulse-mainloop-glib0-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpulse-mainloop-glib0-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpulse0-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpulse0-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-debugsource-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-esound-compat-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-gdm-hooks-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-lang-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-bluetooth-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-bluetooth-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-gconf-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-gconf-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-jack-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-jack-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-lirc-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-lirc-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-x11-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-x11-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-zeroconf-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-module-zeroconf-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-system-wide-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-utils-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pulseaudio-utils-debuginfo-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpulse-mainloop-glib0-32bit-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpulse-mainloop-glib0-debuginfo-32bit-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpulse0-32bit-4.0.git.270.g9490a-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpulse0-debuginfo-32bit-4.0.git.270.g9490a-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpulse-devel / libpulse-mainloop-glib0-32bit / etc");
}
