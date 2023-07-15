#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-61.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106221);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10800", "CVE-2017-11141", "CVE-2017-11529", "CVE-2017-11644", "CVE-2017-11724", "CVE-2017-12434", "CVE-2017-12564", "CVE-2017-12667", "CVE-2017-12670", "CVE-2017-12672", "CVE-2017-12675", "CVE-2017-13060", "CVE-2017-13146", "CVE-2017-13648", "CVE-2017-13658", "CVE-2017-14326", "CVE-2017-14533", "CVE-2017-17881", "CVE-2017-18022", "CVE-2018-5246", "CVE-2018-5247");

  script_name(english:"openSUSE Security Update : ImageMagick (openSUSE-2018-61)");
  script_summary(english:"Check for the openSUSE-2018-61 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes several issues.

These security issues were fixed :

  - CVE-2018-5246: Fixed memory leak vulnerability in
    ReadPATTERNImage in coders/pattern.c (bsc#1074973)

  - CVE-2017-18022: Fixed memory leak vulnerability in
    MontageImageCommand in MagickWand/montage.c
    (bsc#1074975)

  - CVE-2018-5247: Fixed memory leak vulnerability in
    ReadRLAImage in coders/rla.c (bsc#1074969)

  - CVE-2017-12672: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service (bsc#1052720)

  - CVE-2017-13060: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service via a crafted
    file (bsc#1055065)

  - CVE-2017-11724: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c involving the
    quantum_info and clone_info data structures
    (bsc#1051446)

  - CVE-2017-12670: Added validation in coders/mat.c to
    prevent an assertion failure in the function
    DestroyImage in MagickCore/image.c, which allowed
    attackers to cause a denial of service (bsc#1052731)

  - CVE-2017-12667: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c (bsc#1052732)

  - CVE-2017-13146: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c (bsc#1055323)

  - CVE-2017-10800: Processing MATLAB images in coders/mat.c
    could have lead to a denial of service (OOM) in
    ReadMATImage() if the size specified for a MAT Object
    was larger than the actual amount of data (bsc#1047044)

  - CVE-2017-13648: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c (bsc#1055434)

  - CVE-2017-11141: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders\mat.c that could have
    caused memory exhaustion via a crafted MAT file, related
    to incorrect ordering of a SetImageExtent call
    (bsc#1047898)

  - CVE-2017-11529: The ReadMATImage function in
    coders/mat.c allowed remote attackers to cause a denial
    of service (memory leak) via a crafted file
    (bsc#1050120)

  - CVE-2017-12564: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service (bsc#1052468)

  - CVE-2017-12434: Added a missing NULL check in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service (assertion
    failure) in DestroyImageInfo in image.c (bsc#1052550)

  - CVE-2017-12675: Added a missing check for
    multidimensional data coders/mat.c, that could have lead
    to a memory leak in the function ReadImage in
    MagickCore/constitute.c, which allowed attackers to
    cause a denial of service (bsc#1052710)

  - CVE-2017-14326: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service via a crafted
    file (bsc#1058640)

  - CVE-2017-11644: Processesing a crafted file in convert
    could have lead to a memory leak in the ReadMATImage()
    function in coders/mat.c (bsc#1050606)

  - CVE-2017-13658: Added a missing NULL check in the
    ReadMATImage function in coders/mat.c, which could have
    lead to a denial of service (assertion failure and
    application exit) in the DestroyImageInfo function in
    MagickCore/image.c (bsc#1055855)

  - CVE-2017-14533: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c (bsc#1059751)

  - CVE-2017-17881: Fixed a memory leak vulnerability in the
    function ReadMATImage in coders/mat.c, which allowed
    attackers to cause a denial of service via a crafted MAT
    image file (bsc#1074123)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074975"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ImageMagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ImageMagick-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-6_Q16-3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagick++-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickCore-6_Q16-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libMagickWand-6_Q16-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PerlMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/22");
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

if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debuginfo-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-debugsource-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-devel-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ImageMagick-extra-debuginfo-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagick++-devel-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-PerlMagick-debuginfo-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-30.21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-debuginfo-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-debugsource-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-devel-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-extra-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ImageMagick-extra-debuginfo-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-6_Q16-3-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagick++-devel-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickCore-6_Q16-1-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickWand-6_Q16-1-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-PerlMagick-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-PerlMagick-debuginfo-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ImageMagick-devel-32bit-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-32bit-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-32bit-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagick++-devel-32bit-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-32bit-6.8.8.1-49.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-32bit-6.8.8.1-49.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-debuginfo / ImageMagick-debugsource / etc");
}
