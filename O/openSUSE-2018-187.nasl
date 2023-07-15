#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-187.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106919);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-2887");

  script_name(english:"openSUSE Security Update : SDL_image / SDL2_image (openSUSE-2018-187)");
  script_summary(english:"Check for the openSUSE-2018-187 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for SDL_image and SDL2_image fixes the following security
issue :

  - CVE-2017-2887: A specially crafted file could have been
    used to cause a stack overflow resulting in potential
    code execution (bsc#1062777)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062777"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected SDL_image / SDL2_image packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:SDL2_image-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:SDL_image-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL2_image-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL_image-1_2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL_image-1_2-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL_image-1_2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL_image-1_2-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL_image-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libSDL_image-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.3", reference:"SDL2_image-debugsource-2.0.0-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"SDL_image-debugsource-1.2.12-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL2_image-2_0-0-2.0.0-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL2_image-2_0-0-debuginfo-2.0.0-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL2_image-devel-2.0.0-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL_image-1_2-0-1.2.12-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL_image-1_2-0-debuginfo-1.2.12-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libSDL_image-devel-1.2.12-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL2_image-2_0-0-32bit-2.0.0-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL2_image-2_0-0-debuginfo-32bit-2.0.0-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL2_image-devel-32bit-2.0.0-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL_image-1_2-0-32bit-1.2.12-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL_image-1_2-0-debuginfo-32bit-1.2.12-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libSDL_image-devel-32bit-1.2.12-16.3.1") ) flag++;

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
