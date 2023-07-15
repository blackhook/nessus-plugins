#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-280.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108444);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12122", "CVE-2017-14440", "CVE-2017-14441", "CVE-2017-14442", "CVE-2017-14448", "CVE-2017-14449", "CVE-2017-14450");

  script_name(english:"openSUSE Security Update : SDL2 / SDL2_image (openSUSE-2018-280)");
  script_summary(english:"Check for the openSUSE-2018-280 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for SDL2 and SDL2_image fixes the following issues :

  - CVE-2017-14441: Code execution in the ICO image
    rendering (bsc#1084282).

  - CVE-2017-14440: Potential code execution in the ILBM
    image rendering functionality (bsc#1084257).

  - CVE-2017-12122: Potential code execution in the ILBM
    image rendering fuctionality (bsc#1084256).

  - CVE-2017-14448: Heap buffer overflow in the XCF image
    rendering functionality (bsc#1084303).

  - CVE-2017-14449: Double-Free in the XCF image rendering
    (bsc#1084297).

  - CVE-2017-14442: Stack-based buffer overflow the BMP
    image rendering functionality (bsc#1084304).

  - CVE-2017-14450: Buffer overflow in the GIF image parsing
    (bsc#1084288).

Bug fixes :

  - boo#1025413: Add dbus-ime.diff and build with fcitx."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084304"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected SDL2 / SDL2_image packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:SDL2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:SDL2_image-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"SDL2-debugsource-2.0.8-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"SDL2_image-debugsource-2.0.3-13.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL2-2_0-0-2.0.8-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL2-2_0-0-debuginfo-2.0.8-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL2-devel-2.0.8-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL2_image-2_0-0-2.0.3-13.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL2_image-2_0-0-debuginfo-2.0.3-13.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL2_image-devel-2.0.3-13.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL2-2_0-0-32bit-2.0.8-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL2-2_0-0-debuginfo-32bit-2.0.8-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL2-devel-32bit-2.0.8-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL2_image-2_0-0-32bit-2.0.3-13.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL2_image-2_0-0-debuginfo-32bit-2.0.3-13.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL2_image-devel-32bit-2.0.3-13.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SDL2-debugsource / libSDL2-2_0-0 / libSDL2-2_0-0-32bit / etc");
}
