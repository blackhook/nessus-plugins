#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:1180 and 
# CentOS Errata and Security Advisory 2020:1180 respectively.
#

include("compat.inc");

if (description)
{
  script_id(135354);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/05");

  script_cve_id("CVE-2017-1000476", "CVE-2017-11166", "CVE-2017-12805", "CVE-2017-12806", "CVE-2017-18251", "CVE-2017-18252", "CVE-2017-18254", "CVE-2017-18271", "CVE-2017-18273", "CVE-2018-10177", "CVE-2018-10804", "CVE-2018-10805", "CVE-2018-11656", "CVE-2018-12599", "CVE-2018-12600", "CVE-2018-13153", "CVE-2018-14434", "CVE-2018-14435", "CVE-2018-14436", "CVE-2018-14437", "CVE-2018-15607", "CVE-2018-16328", "CVE-2018-16749", "CVE-2018-16750", "CVE-2018-18544", "CVE-2018-20467", "CVE-2018-8804", "CVE-2018-9133", "CVE-2019-10131", "CVE-2019-10650", "CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11597", "CVE-2019-11598", "CVE-2019-12974", "CVE-2019-12975", "CVE-2019-12976", "CVE-2019-12978", "CVE-2019-12979", "CVE-2019-13133", "CVE-2019-13134", "CVE-2019-13135", "CVE-2019-13295", "CVE-2019-13297", "CVE-2019-13300", "CVE-2019-13301", "CVE-2019-13304", "CVE-2019-13305", "CVE-2019-13306", "CVE-2019-13307", "CVE-2019-13309", "CVE-2019-13310", "CVE-2019-13311", "CVE-2019-13454", "CVE-2019-14980", "CVE-2019-14981", "CVE-2019-15139", "CVE-2019-15140", "CVE-2019-15141", "CVE-2019-16708", "CVE-2019-16709", "CVE-2019-16710", "CVE-2019-16711", "CVE-2019-16712", "CVE-2019-16713", "CVE-2019-17540", "CVE-2019-17541", "CVE-2019-19948", "CVE-2019-19949", "CVE-2019-7175", "CVE-2019-7397", "CVE-2019-7398", "CVE-2019-9956");
  script_xref(name:"RHSA", value:"2020:1180");

  script_name(english:"CentOS 7 : ImageMagick / autotrace / emacs / inkscape (CESA-2020:1180)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1180 advisory.

  - ImageMagick: CPU exhaustion vulnerability in function
    ReadDDSInfo in coders/dds.c (CVE-2017-1000476)

  - ImageMagick: memory leak vulnerability in ReadXWDImage
    function in coders/xwd.c (CVE-2017-11166)

  - ImageMagick: memory exhaustion in function ReadTIFFImage
    causing denial of service (CVE-2017-12805)

  - ImageMagick: memory exhaustion in function format8BIM
    causing denial of service (CVE-2017-12806)

  - ImageMagick: memory leak in ReadPCDImage function in
    coders/pcd.c (CVE-2017-18251)

  - ImageMagick: assertion failure in MogrifyImageList
    function in MagickWand/mogrify.c (CVE-2017-18252)

  - ImageMagick: memory leak in WriteGIFImage function in
    coders/gif.c (CVE-2017-18254)

  - ImageMagick: infinite loop in ReadMIFFImage function in
    coders/miff.c (CVE-2017-18271)

  - ImageMagick: infinite loop ReadTXTImage  in function in
    coders/txt.c (CVE-2017-18273)

  - ImageMagick: Infinite loop in
    coders/png.c:ReadOneMNGImage() allows attackers to cause
    a denial of service via crafted MNG file
    (CVE-2018-10177)

  - ImageMagick: Memory leak in WriteTIFFImage
    (CVE-2018-10804)

  - ImageMagick: Memory leak in ReadYCBCRImage
    (CVE-2018-10805)

  - ImageMagick: memory leak in ReadDCMImage function in
    coders/dcm.c (CVE-2018-11656)

  - ImageMagick: out of bounds write in ReadBMPImage and
    WriteBMPImage in coders/bmp.c (CVE-2018-12599)

  - ImageMagick: out of bounds write ReadDIBImage and
    WriteDIBImage in coders/dib.c (CVE-2018-12600)

  - ImageMagick: memory leak in the XMagickCommand function
    in MagickCore/animate.c (CVE-2018-13153)

  - ImageMagick: memory leak for a colormap in WriteMPCImage
    in coders/mpc.c (CVE-2018-14434)

  - ImageMagick: memory leak in DecodeImage in coders/pcd.c
    (CVE-2018-14435)

  - ImageMagick: memory leak in ReadMIFFImage in
    coders/miff.c (CVE-2018-14436)

  - ImageMagick: memory leak in parse8BIM in coders/meta.c
    (CVE-2018-14437)

  - ImageMagick: CPU Exhaustion via crafted input file
    (CVE-2018-15607)

  - ImageMagick: NULL pointer dereference in
    CheckEventLogging function in MagickCore/log.c
    (CVE-2018-16328)

  - ImageMagick: reachable assertion in ReadOneJNGImage in
    coders/png.c (CVE-2018-16749)

  - ImageMagick: Memory leak in the formatIPTCfromBuffer
    function in coders/meta.c (CVE-2018-16750)

  - ImageMagick: memory leak in WriteMSLImage of
    coders/msl.c (CVE-2018-18544)

  - ImageMagick: infinite loop in coders/bmp.c
    (CVE-2018-20467)

  - ImageMagick: double free in WriteEPTImage function in
    coders/ept.c (CVE-2018-8804)

  - ImageMagick: excessive iteration in the DecodeLabImage
    and EncodeLabImage functions in coders/tiff.c
    (CVE-2018-9133)

  - ImageMagick: off-by-one read in formatIPTCfromBuffer
    function in coders/meta.c (CVE-2019-10131)

  - ImageMagick: heap-based buffer over-read in
    WriteTIFFImage of coders/tiff.c leads to denial of
    service or information disclosure via crafted image file
    (CVE-2019-10650)

  - ImageMagick: denial of service in cineon parsing
    component (CVE-2019-11470)

  - ImageMagick: denial of service in ReadXWDImage in
    coders/xwd.c in the XWD image parsing component
    (CVE-2019-11472)

  - ImageMagick: heap-based buffer over-read in the function
    WriteTIFFImage of coders/tiff.c leading to DoS or
    information disclosure (CVE-2019-11597)

  - ImageMagick: heap-based buffer over-read in the function
    WritePNMImage of coders/pnm.c leading to DoS or
    information disclosure (CVE-2019-11598)

  - imagemagick: null-pointer dereference in function
    ReadPANGOImage in coders/pango.c and ReadVIDImage in
    coders/vid.c causing denial of service (CVE-2019-12974)

  - imagemagick: memory leak vulnerability in function
    WriteDPXImage in coders/dpx.c (CVE-2019-12975)

  - imagemagick: memory leak vulnerability in function
    ReadPCLImage in coders/pcl.c (CVE-2019-12976)

  - imagemagick: use of uninitialized value in function
    ReadPANGOImage in coders/pango.c (CVE-2019-12978)

  - imagemagick: use of uninitialized value in
    functionSyncImageSettings in MagickCore/image.c
    (CVE-2019-12979)

  - ImageMagick: a memory leak vulnerability in the function
    ReadBMPImage in coders/bmp.c (CVE-2019-13133)

  - ImageMagick: a memory leak vulnerability in the function
    ReadVIFFImage in coders/viff.c (CVE-2019-13134)

  - ImageMagick: a use of uninitialized value
    vulnerability in the function ReadCUTImage leading to a
    crash and DoS (CVE-2019-13135)

  - ImageMagick: heap-based buffer over-read at
    MagickCore/threshold.c in AdaptiveThresholdImage because
    a width of zero is mishandled (CVE-2019-13295)

  - ImageMagick: heap-based buffer over-read at
    MagickCore/threshold.c in AdaptiveThresholdImage because
    a height of zero is mishandled (CVE-2019-13297)

  - ImageMagick: heap-based buffer overflow at
    MagickCore/statistic.c in EvaluateImages because of
    mishandling columns (CVE-2019-13300)

  - ImageMagick: memory leaks in AcquireMagickMemory
    (CVE-2019-13301)

  - ImageMagick: stack-based buffer overflow at coders/pnm.c
    in WritePNMImage because of a misplaced assignment
    (CVE-2019-13304)

  - ImageMagick: stack-based buffer overflow at coders/pnm.c
    in WritePNMImage because of a misplaced strncpy and an
    off-by-one error (CVE-2019-13305)

  - ImageMagick: stack-based buffer overflow at coders/pnm.c
    in WritePNMImage because of off-by-one errors
    (CVE-2019-13306)

  - ImageMagick: heap-based buffer overflow at
    MagickCore/statistic.c in EvaluateImages because of
    mishandling rows (CVE-2019-13307)

  - ImageMagick: memory leaks at AcquireMagickMemory due to
    mishandling the NoSuchImage error in
    CLIListOperatorImages (CVE-2019-13309)

  - ImageMagick: memory leaks at AcquireMagickMemory because
    of an error in MagickWand/mogrify.c (CVE-2019-13310)

  - ImageMagick: memory leaks at AcquireMagickMemory because
    of a wand/mogrify.c error (CVE-2019-13311)

  - ImageMagick: division by zero in RemoveDuplicateLayers
    in MagickCore/layer.c (CVE-2019-13454)

  - ImageMagick: use-after-free in magick/blob.c resulting
    in a denial of service (CVE-2019-14980)

  - ImageMagick: division by zero in MeanShiftImage in
    MagickCore/feature.c (CVE-2019-14981)

  - ImageMagick: out-of-bounds read in ReadXWDImage in
    coders/xwd.c (CVE-2019-15139)

  - ImageMagick: Use after free in ReadMATImage in
    coders/mat.c (CVE-2019-15140)

  - ImageMagick: heap-based buffer overflow in
    WriteTIFFImage in coders/tiff.c (CVE-2019-15141)

  - ImageMagick: memory leak in magick/xwindow.c
    (CVE-2019-16708)

  - ImageMagick: memory leak in coders/dps.c
    (CVE-2019-16709)

  - ImageMagick: memory leak in coders/dot.c
    (CVE-2019-16710, CVE-2019-16713)

  - ImageMagick: memory leak in Huffman2DEncodeImage in
    coders/ps2.c (CVE-2019-16711)

  - ImageMagick: memory leak in Huffman2DEncodeImage in
    coders/ps3.c (CVE-2019-16712)

  - ImageMagick: heap-based buffer overflow in ReadPSInfo in
    coders/ps.c (CVE-2019-17540)

  - ImageMagick: Use after free in ReadICCProfile function
    in coders/jpeg.c (CVE-2019-17541)

  - ImageMagick: heap-based buffer overflow in WriteSGIImage
    in coders/sgi.c (CVE-2019-19948)

  - ImageMagick: heap-based buffer over-read in
    WritePNGImage in coders/png.c (CVE-2019-19949)

  - imagemagick: memory leak in function DecodeImage in
    coders/pcd.c (CVE-2019-7175)

  - ImageMagick: Memory leak in the WritePDFImage function
    in coders/pdf.c (CVE-2019-7397)

  - ImageMagick: Memory leak in the WriteDIBImage function
    in coders/dib.c (CVE-2019-7398)

  - imagemagick: stack-based buffer overflow in function
    PopHexPixel in coders/ps.c (CVE-2019-9956)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012410.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f508a75e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012438.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5525b51f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012467.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f4fa0d1"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-April/012470.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f951dbe"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16328");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autotrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autotrace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:emacs-terminal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:inkscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:inkscape-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:inkscape-view");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-c++-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-devel-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-doc-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-perl-6.9.10.68-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autotrace-0.31.1-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"autotrace-devel-0.31.1-38.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-24.3-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-common-24.3-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-el-24.3-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-filesystem-24.3-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-nox-24.3-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"emacs-terminal-24.3-23.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"inkscape-0.92.2-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"inkscape-docs-0.92.2-3.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"inkscape-view-0.92.2-3.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
