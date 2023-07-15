#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-156.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106743);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10244", "CVE-2017-7864", "CVE-2017-8105", "CVE-2017-8287");

  script_name(english:"openSUSE Security Update : freetype2 (openSUSE-2018-156)");
  script_summary(english:"Check for the openSUSE-2018-156 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for freetype2 fixes the following security issues :

  - CVE-2016-10244: Make sure that the parse_charstrings
    function in type1/t1load.c does ensure that a font
    contains a glyph name to prevent a DoS through a
    heap-based buffer over-read or possibly have unspecified
    other impact via a crafted file (bsc#1028103)

  - CVE-2017-8105: Fix an out-of-bounds write caused by a
    heap-based buffer overflow related to the
    t1_decoder_parse_charstrings function in
    psaux/t1decode.ca (bsc#1035807)

  - CVE-2017-8287: an out-of-bounds write caused by a
    heap-based buffer overflow related to the
    t1_builder_close_contour function in psaux/psobjs.c
    (bsc#1036457)

  - Fix several integer overflow issues in
    truetype/ttinterp.c (bsc#1079600)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079600"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ft2demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/12");
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

if ( rpm_check(release:"SUSE42.3", reference:"freetype2-debugsource-2.6.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freetype2-devel-2.6.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ft2demos-2.6.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreetype6-2.6.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libfreetype6-debuginfo-2.6.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"freetype2-devel-32bit-2.6.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libfreetype6-32bit-2.6.3-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libfreetype6-debuginfo-32bit-2.6.3-5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype2-debugsource / freetype2-devel / freetype2-devel-32bit / etc");
}
