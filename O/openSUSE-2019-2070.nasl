#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2070.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128539);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2019-12217", "CVE-2019-12218", "CVE-2019-12220", "CVE-2019-12221", "CVE-2019-12222", "CVE-2019-13616", "CVE-2019-5051", "CVE-2019-5052", "CVE-2019-5057", "CVE-2019-5058", "CVE-2019-5059", "CVE-2019-5060");

  script_name(english:"openSUSE Security Update : SDL2_image (openSUSE-2019-2070)");
  script_summary(english:"Check for the openSUSE-2019-2070 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for SDL2_image fixes the following issues :

Update to new upstream release 2.0.5.

Security issues fixed :

  - TALOS-2019-0820 CVE-2019-5051: exploitable heap-based
    buffer overflow vulnerability when loading a PCX file
    (boo#1140419)

  - TALOS-2019-0821 CVE-2019-5052: exploitable integer
    overflow vulnerability when loading a PCX file
    (boo#1140421)

  - TALOS-2019-0841 CVE-2019-5057: code execution
    vulnerability in the PCX image-rendering functionality
    of SDL2_image (boo#1143763)

  - TALOS-2019-0842 CVE-2019-5058: heap overflow in XCF
    image rendering can lead to code execution (boo#1143764)

  - TALOS-2019-0843 CVE-2019-5059: heap overflow in XPM
    image (boo#1143766)

  - TALOS-2019-0844 CVE-2019-5060: integer overflow in the
    XPM image (boo#1143768)

Not mentioned by upstream, but issues seemingly further fixed :

  - CVE-2019-12218: NULL pointer dereference in the
    SDL2_image function IMG_LoadPCX_RW (boo#1135789)

  - CVE-2019-12217: NULL pointer dereference in the SDL
    stdio_read function (boo#1135787)

  - CVE-2019-12220: SDL_image triggers an out-of-bounds read
    in the SDL function SDL_FreePalette_REAL (boo#1135806)

  - CVE-2019-12221: a SEGV caused by SDL_image in SDL
    function SDL_free_REAL in stdlib/SDL_malloc.c
    (boo#1135796)

  - CVE-2019-12222: out-of-bounds read triggered by
    SDL_image in the function SDL_InvalidateMap at
    video/SDL_pixels.c (boo#1136101)

  - CVE-2019-13616: fix heap buffer overflow when reading a
    crafted bmp file (boo#1141844)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1141844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143768"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected SDL2_image packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:SDL2_image-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"SDL2_image-debugsource-2.0.5-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libSDL2_image-2_0-0-2.0.5-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libSDL2_image-2_0-0-debuginfo-2.0.5-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libSDL2_image-devel-2.0.5-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libSDL2_image-2_0-0-32bit-2.0.5-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libSDL2_image-2_0-0-32bit-debuginfo-2.0.5-lp151.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libSDL2_image-devel-32bit-2.0.5-lp151.2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SDL2_image-debugsource / libSDL2_image-2_0-0 / etc");
}
