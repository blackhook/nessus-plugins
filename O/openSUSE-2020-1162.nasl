#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1162.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139446);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/12");

  script_cve_id("CVE-2020-14344");

  script_name(english:"openSUSE Security Update : libX11 (openSUSE-2020-1162)");
  script_summary(english:"Check for the openSUSE-2020-1162 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libX11 fixes the following issues :

  - Fixed XIM client heap overflows (CVE-2020-14344,
    bsc#1174628)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174628"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libX11 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libX11-xcb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-composite0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-damage0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dpms0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri3-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri3-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-dri3-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-glx0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-present0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-present0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-present0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-present0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-randr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-record0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-render0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-res0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-screensaver0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shape0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-shm0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-sync1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xf86dri0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xfixes0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinerama0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinput0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinput0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinput0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xinput0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xkb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xkb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xkb1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xkb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xtest0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xv0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb-xvmc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxcb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libX11-6-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libX11-6-debuginfo-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libX11-data-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libX11-debugsource-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libX11-devel-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libX11-xcb1-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libX11-xcb1-debuginfo-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-composite0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-composite0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-damage0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-damage0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-debugsource-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-devel-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-dpms0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-dpms0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-dri2-0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-dri2-0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-dri3-0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-dri3-0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-glx0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-glx0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-present0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-present0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-randr0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-randr0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-record0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-record0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-render0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-render0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-res0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-res0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-screensaver0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-screensaver0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-shape0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-shape0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-shm0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-shm0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-sync1-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-sync1-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xf86dri0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xf86dri0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xfixes0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xfixes0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xinerama0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xinerama0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xinput0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xinput0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xkb1-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xkb1-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xtest0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xtest0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xv0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xv0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xvmc0-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb-xvmc0-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb1-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxcb1-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libX11-6-32bit-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libX11-6-32bit-debuginfo-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libX11-devel-32bit-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libX11-xcb1-32bit-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libX11-xcb1-32bit-debuginfo-1.6.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-composite0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-composite0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-damage0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-damage0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-devel-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-dpms0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-dpms0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-dri2-0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-dri2-0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-dri3-0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-dri3-0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-glx0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-glx0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-present0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-present0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-randr0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-randr0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-record0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-record0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-render0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-render0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-res0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-res0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-screensaver0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-screensaver0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-shape0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-shape0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-shm0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-shm0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-sync1-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-sync1-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xf86dri0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xf86dri0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xfixes0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xfixes0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xinerama0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xinerama0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xinput0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xinput0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xkb1-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xkb1-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xtest0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xtest0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xv0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xv0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xvmc0-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb-xvmc0-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb1-32bit-1.13-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxcb1-32bit-debuginfo-1.13-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libX11-6 / libX11-6-debuginfo / libX11-data / libX11-debugsource / etc");
}
