#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-88.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106357);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11750", "CVE-2017-12641", "CVE-2017-12673", "CVE-2017-12676", "CVE-2017-12935", "CVE-2017-13142", "CVE-2017-13147", "CVE-2017-14103", "CVE-2017-15218", "CVE-2017-9261", "CVE-2017-9262");

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-2018-88)");
  script_summary(english:"Check for the openSUSE-2018-88 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for GraphicsMagick fixes several issues.

These security issues were fixed :

  - CVE-2017-9262: The ReadJNGImage function in coders/png.c
    allowed attackers to cause a denial of service (memory
    leak) via a crafted file (bsc#1043353)

  - CVE-2017-9261: The ReadMNGImage function in coders/png.c
    allowed attackers to cause a denial of service (memory
    leak) via a crafted file (bsc#1043354)

  - CVE-2017-11750: The ReadOneJNGImage function in
    coders/png.c allowed remote attackers to cause a denial
    of service (NULL pointer dereference) via a crafted file
    (bsc#1051442)

  - CVE-2017-12676: Prevent memory leak in the function
    ReadOneJNGImage in coders/png.c, which allowed attackers
    to cause a denial of service (bsc#1052708)

  - CVE-2017-12673: Prevent memory leak in the function
    ReadOneMNGImage in coders/png.c, which allowed attackers
    to cause a denial of service (bsc#1052717)

  - CVE-2017-12641: Prevent a memory leak vulnerability in
    ReadOneJNGImage in coders\png.c (bsc#1052777)

  - CVE-2017-12935: The ReadMNGImage function in
    coders/png.c mishandled large MNG images, leading to an
    invalid memory read in the SetImageColorCallBack
    function in magick/image.c (bsc#1054600)

  - CVE-2017-13147: Prevent allocation failure in the
    function ReadMNGImage in coders/png.c when a small MNG
    file has a MEND chunk with a large length value
    (bsc#1055374)

  - CVE-2017-13142: Added additional checks for short files
    to prevent a crafted PNG file from triggering a crash
    (bsc#1055455)

  - CVE-2017-14103: The ReadJNGImage and ReadOneJNGImage
    functions in coders/png.c did not properly manage image
    pointers after certain error conditions, which allowed
    remote attackers to conduct use-after-free attacks via a
    crafted file, related to a ReadMNGImage out-of-order
    CloseBlob call (bsc#1057000)

  - CVE-2017-15218: Prevent memory leak in ReadOneJNGImage
    in coders/png.c (bsc#1062752)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062752"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick3-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/26");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"GraphicsMagick-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"GraphicsMagick-debuginfo-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"GraphicsMagick-debugsource-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"GraphicsMagick-devel-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libGraphicsMagick++-Q16-12-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libGraphicsMagick++-Q16-12-debuginfo-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libGraphicsMagick++-devel-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libGraphicsMagick-Q16-3-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libGraphicsMagick3-config-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libGraphicsMagickWand-Q16-2-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-GraphicsMagick-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-GraphicsMagick-debuginfo-1.3.25-11.63.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-debuginfo-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-debugsource-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-devel-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick++-Q16-12-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick++-Q16-12-debuginfo-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick++-devel-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick-Q16-3-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick3-config-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagickWand-Q16-2-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-GraphicsMagick-1.3.25-60.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-GraphicsMagick-debuginfo-1.3.25-60.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-debuginfo / etc");
}
