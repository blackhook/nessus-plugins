#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-179.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96917);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"openSUSE Security Update : lcms2 (openSUSE-2017-179)");
  script_summary(english:"Check for the openSUSE-2017-179 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"&#9;&#9;&#9;&#9; This update for lcms2 to version 2.8 fixes the
following issues :

&#9;&#9;&#9;&#9; This security issue was fixed :

&#9;&#9;&#9;&#9; - Fixed an out-of-bounds heap read in
Type_MLU_Read that could be triggered by an untrusted image
with a crafted ICC profile (boo#1021364).

&#9;&#9;&#9;&#9; These non-security issues were fixed :

&#9;&#9;&#9;&#9; - Fixed many typos in comments, thanks to
Stefan Weil for doing that.

&#9;&#9;&#9;&#9; - Fixed localization bug, added a new test
case crayons.icc thnaks to Richard Hughes for providing the
profile.

&#9;&#9;&#9;&#9; - Fixed a bug in optimizer that made some
formats (i.e, bits planar) unavailable

&#9;&#9;&#9;&#9; - Fixed misalignment problems on Alpha. The
compiler does not align strings, and accessing begin of
string as a uint16 makes code to fail.

&#9;&#9;&#9;&#9; - Added some extra checks to the tools and
examples.

&#9;&#9;&#9;&#9; - Fix a bug that prevented to read
luminance tag

&#9;&#9;&#9;&#9; - BIG amount of functionality
contributed/Sponsored by Alien Skin Software:
TransformStride, copyAlpha, performance plug-ins. Fixes some
warnings as well.

&#9;&#9;&#9;&#9; - added an extra _ to _stdcall to make it
more portable

&#9;&#9;&#9;&#9; - Fixed a bug in transicc for named color
profiles

&#9;&#9;&#9;&#9; - Fixed several compiler warnings

&#9;&#9;&#9;&#9; - Added support for Visual Studio 2015

&#9;&#9;&#9;&#9; - Fixed for XCODE project

&#9;&#9;&#9;&#9; - Update to GNOME 3.20 &#9;&#9;&#9;"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021364"
  );
  # https://features.opensuse.org/318572
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lcms2 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lcms2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lcms2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lcms2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblcms2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblcms2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblcms2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblcms2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblcms2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblcms2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"lcms2-2.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"lcms2-debuginfo-2.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"lcms2-debugsource-2.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liblcms2-2-2.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liblcms2-2-debuginfo-2.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"liblcms2-devel-2.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"liblcms2-2-32bit-2.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"liblcms2-2-debuginfo-32bit-2.8-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"liblcms2-devel-32bit-2.8-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lcms2 / lcms2-debuginfo / lcms2-debugsource / liblcms2-2 / etc");
}
