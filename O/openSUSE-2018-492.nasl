#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-492.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110066);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-1516", "CVE-2017-12597", "CVE-2017-12598", "CVE-2017-12599", "CVE-2017-12600", "CVE-2017-12601", "CVE-2017-12602", "CVE-2017-12603", "CVE-2017-12604", "CVE-2017-12605", "CVE-2017-12606", "CVE-2017-12862", "CVE-2017-12863", "CVE-2017-12864", "CVE-2017-14136");

  script_name(english:"openSUSE Security Update : opencv (openSUSE-2018-492)");
  script_summary(english:"Check for the openSUSE-2018-492 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for opencv fixes the following issues :

Security issues fixed :

  - CVE-2016-1516: OpenCV had a double free issue that
    allowed attackers to execute arbitrary code.
    (boo#1033152)

  - CVE-2017-14136: OpenCV had an out-of-bounds write error
    in the function FillColorRow1 in utils.cpp when reading
    an image file by using cv::imread. NOTE: this
    vulnerability exists because of an incomplete fix for
    CVE-2017-12597. (boo#1057146)

  - CVE-2017-12606: OpenCV had an out-of-bounds write error
    in the function FillColorRow4 in utils.cpp when reading
    an image file by using cv::imread. (boo#1052451)

  - CVE-2017-12604: OpenCV had an out-of-bounds write error
    in the FillUniColor function in utils.cpp when reading
    an image file by using cv::imread. (boo#1052454)

  - CVE-2017-12603: OpenCV had an invalid write in the
    cv::RLByteStream::getBytes function in
    modules/imgcodecs/src/bitstrm.cpp when reading an image
    file by using cv::imread, as demonstrated by the
    2-opencv-heapoverflow-fseek test case. (boo#1052455)

  - CVE-2017-12602: OpenCV had a denial of service (memory
    consumption) issue, as demonstrated by the
    10-opencv-dos-memory-exhaust test case. (boo#1052456)

  - CVE-2017-12601: OpenCV had a buffer overflow in the
    cv::BmpDecoder::readData function in
    modules/imgcodecs/src/grfmt_bmp.cpp when reading an
    image file by using cv::imread, as demonstrated by the
    4-buf-overflow-readData-memcpy test case. (boo#1052457)

  - CVE-2017-12600: OpenCV had a denial of service (CPU
    consumption) issue, as demonstrated by the
    11-opencv-dos-cpu-exhaust test case. (boo#1052459)

  - CVE-2017-12599: OpenCV had an out-of-bounds read error
    in the function icvCvt_BGRA2BGR_8u_C4C3R when reading an
    image file by using cv::imread. (boo#1052461)

  - CVE-2017-12598: OpenCV had an out-of-bounds read error
    in the cv::RBaseStream::readBlock function in
    modules/imgcodecs/src/bitstrm.cpp when reading an image
    file by using cv::imread, as demonstrated by the
    8-opencv-invalid-read-fread test case. (boo#1052462)

  - CVE-2017-12597: OpenCV had an out-of-bounds write error
    in the function FillColorRow1 in utils.cpp when reading
    an image file by using cv::imread. (boo#1052465)

  - CVE-2017-12864: In
    opencv/modules/imgcodecs/src/grfmt_pxm.cpp, function
    ReadNumber did not checkout the input length, which lead
    to integer overflow. If the image is from remote, may
    lead to remote code execution or denial of service.
    (boo#1054019)

  - CVE-2017-12863: In
    opencv/modules/imgcodecs/src/grfmt_pxm.cpp, function
    PxMDecoder::readData has an integer overflow when
    calculate src_pitch. If the image is from remote, may
    lead to remote code execution or denial of service.
    (boo#1054020)

  - CVE-2017-12862: In modules/imgcodecs/src/grfmt_pxm.cpp,
    the length of buffer AutoBuffer _src is small than
    expected, which will cause copy buffer overflow later.
    If the image is from remote, may lead to remote code
    execution or denial of service. (boo#1054021)

  - CVE-2017-12605: OpenCV had an out-of-bounds write error
    in the FillColorRow8 function in utils.cpp when reading
    an image file by using cv::imread. (boo#1054984)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057146"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected opencv packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv-qt56_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv-qt56_3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv3_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv3_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-qt5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-qt5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-opencv-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-opencv-qt5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv-qt5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libopencv-qt56_3-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopencv-qt56_3-debuginfo-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopencv3_1-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopencv3_1-debuginfo-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-debuginfo-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-debugsource-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-devel-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-qt5-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-qt5-debuginfo-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-qt5-debugsource-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-qt5-devel-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-opencv-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-opencv-debuginfo-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-opencv-qt5-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-opencv-qt5-debuginfo-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-opencv-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-opencv-debuginfo-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-opencv-qt5-3.1.0-4.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-opencv-qt5-debuginfo-3.1.0-4.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopencv-qt56_3 / libopencv-qt56_3-debuginfo / opencv-qt5 / etc");
}
