#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-407.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109521);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11641", "CVE-2017-13066", "CVE-2017-18229", "CVE-2017-18251", "CVE-2017-18254", "CVE-2018-10177", "CVE-2018-6799", "CVE-2018-9018");

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-2018-407)");
  script_summary(english:"Check for the openSUSE-2018-407 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for GraphicsMagick fixes the following issues :

  - security update (core)

  - CVE-2018-6799: The AcquireCacheNexus function in
    magick/pixel_cache.c in GraphicsMagick before 1.3.28
    allows remote attackers to cause a denial of service
    (heap overwrite) or possibly have unspecified other
    impact via a crafted image file, because a pixel staging
    area is not used. [boo#1080522]

  - security update (png.c)

  - CVE-2018-9018: In GraphicsMagick 1.3.28, there is a
    divide-by-zero in the ReadMNGImage function of
    coders/png.c. Remote attackers could leverage this
    vulnerability to cause a crash and denial of service via
    a crafted mng file. [boo#1086773]

  - security update (gif.c)

  - CVE-2017-18254: An issue was discovered in ImageMagick
    7.0.7. A memory leak vulnerability was found in the
    function WriteGIFImage in coders/gif.c, which allow
    remote attackers to cause a denial of service via a
    crafted file. [boo#1087027]

  - security update (pcd.c)

  - CVE-2017-18251: An issue was discovered in ImageMagick
    7.0.7. A memory leak vulnerability was found in the
    function ReadPCDImage in coders/pcd.c, which allow
    remote attackers to cause a denial of service via a
    crafted file. [boo#1087037]

  - CVE-2017-18229: An issue was discovered in
    GraphicsMagick 1.3.26. An allocation failure
    vulnerability was found in the function ReadTIFFImage in
    coders/tiff.c, which allows attackers to cause a denial
    of service via a crafted file, because file size is not
    properly used to restrict scanline, strip, and tile
    allocations. [boo#1085236]

  - CVE-2017-11641: GraphicsMagick 1.3.26 has a Memory Leak
    in the PersistCache function in magick/pixel_cache.c
    during writing of Magick Persistent Cache (MPC)
    files.[boo#1050623]

  - CVE-2017-13066: GraphicsMagick 1.3.26 has a memory leak
    vulnerability in the function CloneImage in
    magick/image.c. [boo#1055010]

  - CVE-2018-10177: Specially crafted PNG images may have
    triggered an infinite loop [bsc#1089781]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1089781"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected GraphicsMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/02");
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

if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-debuginfo-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-debugsource-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"GraphicsMagick-devel-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick++-Q16-12-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick++-Q16-12-debuginfo-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick++-devel-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick-Q16-3-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagick3-config-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagickWand-Q16-2-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-GraphicsMagick-1.3.25-87.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-GraphicsMagick-debuginfo-1.3.25-87.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-debuginfo / etc");
}
