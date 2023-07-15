#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1391.
#

include("compat.inc");

if (description)
{
  script_id(138633);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2017-1000476", "CVE-2017-11166", "CVE-2017-12805", "CVE-2017-12806", "CVE-2017-18251", "CVE-2017-18252", "CVE-2017-18254", "CVE-2017-18271", "CVE-2017-18273", "CVE-2018-10177", "CVE-2018-10804", "CVE-2018-10805", "CVE-2018-11656", "CVE-2018-12599", "CVE-2018-12600", "CVE-2018-13153", "CVE-2018-14434", "CVE-2018-14435", "CVE-2018-14436", "CVE-2018-14437", "CVE-2018-15607", "CVE-2018-16328", "CVE-2018-16749", "CVE-2018-16750", "CVE-2018-18544", "CVE-2018-20467", "CVE-2018-8804", "CVE-2018-9133", "CVE-2019-10131", "CVE-2019-10650", "CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11597", "CVE-2019-11598", "CVE-2019-12974", "CVE-2019-12975", "CVE-2019-12976", "CVE-2019-12978", "CVE-2019-12979", "CVE-2019-13133", "CVE-2019-13134", "CVE-2019-13135", "CVE-2019-13295", "CVE-2019-13297", "CVE-2019-13300", "CVE-2019-13301", "CVE-2019-13304", "CVE-2019-13305", "CVE-2019-13306", "CVE-2019-13307", "CVE-2019-13309", "CVE-2019-13310", "CVE-2019-13311", "CVE-2019-13454", "CVE-2019-14980", "CVE-2019-14981", "CVE-2019-15139", "CVE-2019-15140", "CVE-2019-15141", "CVE-2019-16708", "CVE-2019-16709", "CVE-2019-16710", "CVE-2019-16711", "CVE-2019-16712", "CVE-2019-16713", "CVE-2019-17540", "CVE-2019-17541", "CVE-2019-19948", "CVE-2019-19949", "CVE-2019-7175", "CVE-2019-7397", "CVE-2019-7398", "CVE-2019-9956");
  script_xref(name:"ALAS", value:"2020-1391");

  script_name(english:"Amazon Linux AMI : php-pecl-imagick (ALAS-2020-1391)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An issue was discovered in ImageMagick 7.0.7. A memory leak
vulnerability was found in the function WriteGIFImage in coders/gif.c,
which allow remote attackers to cause a denial of service via a
crafted file. (CVE-2017-18254)

An issue was discovered in ImageMagick 7.0.7. The MogrifyImageList
function in MagickWand/mogrify.c allows attackers to cause a denial of
service (assertion failure and application exit in ReplaceImageInList)
via a crafted file. (CVE-2017-18252)

An issue was discovered in ImageMagick 7.0.7. A memory leak
vulnerability was found in the function ReadPCDImage in coders/pcd.c,
which allow remote attackers to cause a denial of service via a
crafted file. (CVE-2017-18251)

In ImageMagick 7.0.7-29 and earlier, a missing NULL check in
ReadOneJNGImage in coders/png.c allows an attacker to cause a denial
of service (WriteBlob assertion failure and application exit) via a
crafted file. (CVE-2018-16749)

ImageMagick 7.0.8-34 has a 'use of uninitialized value' vulnerability
in the ReadPANGOImage function in coders/pango.c. (CVE-2019-12978)

The ReadXWDImage function in coders\xwd.c in ImageMagick 7.0.5-6 has a
memory leak vulnerability that can cause memory exhaustion via a
crafted length (number of color-map entries) field in the header of an
XWD file. (CVE-2017-11166)

In ImageMagick 7.0.8-4, there is a memory leak in the XMagickCommand
function in MagickCore/animate.c. (CVE-2018-13153)

ImageMagick 7.0.8-4 has a memory leak in DecodeImage in coders/pcd.c.
(CVE-2018-14435)

ImageMagick 7.0.8-4 has a memory leak for a colormap in WriteMPCImage
in coders/mpc.c. (CVE-2018-14434)

ImageMagick 7.0.8-4 has a memory leak in parse8BIM in coders/meta.c.
(CVE-2018-14437)

ImageMagick 7.0.8-4 has a memory leak in ReadMIFFImage in
coders/miff.c. (CVE-2018-14436)

ImageMagick 7.0.8-34 has a memory leak in the ReadPCLImage function in
coders/pcl.c. (CVE-2019-12976)

ImageMagick 7.0.8-50 Q16 has memory leaks at AcquireMagickMemory
because of a wand/mogrify.c error. (CVE-2019-13311)

ImageMagick before 7.0.8-55 has a use-after-free in DestroyStringInfo
in MagickCore/string.c because the error manager is mishandled in
coders/jpeg.c. (CVE-2019-17541)

ImageMagick before 7.0.8-54 has a heap-based buffer overflow in
ReadPSInfo in coders/ps.c. (CVE-2019-17540)

In ImageMagick 7.x before 7.0.8-42 and 6.x before 6.9.10-42, there is
a use after free vulnerability in the UnmapBlob function that allows
an attacker to cause a denial of service by sending a crafted file.
(CVE-2019-14980)

In ImageMagick 7.x before 7.0.8-41 and 6.x before 6.9.10-41, there is
a divide-by-zero vulnerability in the MeanShiftImage function. It
allows an attacker to cause a denial of service by sending a crafted
file. (CVE-2019-14981)

In ImageMagick 7.0.8-35 Q16, there is a stack-based buffer overflow in
the function PopHexPixel of coders/ps.c, which allows an attacker to
cause a denial of service or code execution via a crafted image file.
(CVE-2019-9956)

In ImageMagick before 7.0.8-25 and GraphicsMagick through 1.3.31,
several memory leaks exist in WritePDFImage in coders/pdf.c.
(CVE-2019-7397)

coders/mat.c in ImageMagick 7.0.8-43 Q16 allows remote attackers to
cause a denial of service (use-after-free and application crash) or
possibly have unspecified other impact by crafting a Matlab image file
that is mishandled in ReadImage in MagickCore/constitute.c.
(CVE-2019-11597)

In ImageMagick 7.0.6-6, a memory exhaustion vulnerability was found in
the function ReadTIFFImage, which allows attackers to cause a denial
of service. (CVE-2019-15140)

In ImageMagick 7.0.6-6, a memory exhaustion vulnerability was found in
the function format8BIM, which allows attackers to cause a denial of
service. (CVE-2017-12806)

In ImageMagick 7.0.8-36 Q16, there is a heap-based buffer over-read in
the function WriteTIFFImage of coders/tiff.c, which allows an attacker
to cause a denial of service or information disclosure via a crafted
image file. (CVE-2019-10650)

ImageMagick 7.0.8-35 has a memory leak in magick/xwindow.c, related to
XCreateImage. (CVE-2019-16708)

ImageMagick 7.0.8-35 has a memory leak in coders/dps.c, as
demonstrated by XCreateImage. (CVE-2019-16709)

ImageMagick before 7.0.8-50 has a memory leak vulnerability in the
function ReadBMPImage in coders/bmp.c. (CVE-2019-13133)

ImageMagick before 7.0.8-50 has a memory leak vulnerability in the
function ReadVIFFImage in coders/viff.c. (CVE-2019-13134)

ImageMagick before 7.0.8-50 has a 'use of uninitialized value'
vulnerability in the function ReadCUTImage in coders/cut.c.
(CVE-2019-13135)

In ImageMagick before 7.0.8-25, some memory leaks exist in DecodeImage
in coders/pcd.c. (CVE-2019-7175)

In ImageMagick 7.0.8-40 Q16, there is a heap-based buffer over-read in
the function WritePNMImage of coders/pnm.c, which allows an attacker
to cause a denial of service or possibly information disclosure via a
crafted image file. This is related to SetGrayscaleImage in
MagickCore/quantize.c. (CVE-2019-11598)

ImageMagick 7.0.8-50 Q16 has memory leaks at AcquireMagickMemory
because of an error in MagickWand/mogrify.c. (CVE-2019-13310)

In ImageMagick 7.0.7-16 Q16 x86_64 2017-12-22, an infinite loop
vulnerability was found in the function ReadMIFFImage in
coders/miff.c, which allows attackers to cause a denial of service
(CPU exhaustion) via a crafted MIFF image file. (CVE-2017-18271)

In ImageMagick 7.0.7-16 Q16 x86_64 2017-12-22, an infinite loop
vulnerability was found in the function ReadTXTImage in coders/txt.c,
which allows attackers to cause a denial of service (CPU exhaustion)
via a crafted image file that is mishandled in a GetImageIndexInList
call. (CVE-2017-18273)

There is a memory leak in the function WriteMSLImage of coders/msl.c
in ImageMagick 7.0.8-13 Q16, and the function ProcessMSLScript of
coders/msl.c in GraphicsMagick before 1.3.31. (CVE-2018-18544)

In ImageMagick 7.0.8-11 Q16, a tiny input file 0x50 0x36 0x36 0x36
0x36 0x4c 0x36 0x38 0x36 0x36 0x36 0x36 0x36 0x36 0x1f 0x35 0x50 0x00
can result in a hang of several minutes during which CPU and memory
resources are consumed until ultimately an attempted large memory
allocation fails. Remote attackers could leverage this vulnerability
to cause a denial of service via a crafted file. (CVE-2018-15607)

ImageMagick 7.0.8-43 has a memory leak in coders/dot.c, as
demonstrated by PingImage in MagickCore/constitute.c. (CVE-2019-16713)

ImageMagick 7.0.8-43 has a memory leak in Huffman2DEncodeImage in
coders/ps3.c, as demonstrated by WritePS3Image. (CVE-2019-16712)

ImageMagick 7.0.8-40 has a memory leak in Huffman2DEncodeImage in
coders/ps2.c. (CVE-2019-16711)

ImageMagick 7.0.8-35 has a memory leak in coders/dot.c, as
demonstrated by AcquireMagickMemory in MagickCore/memory.c.
(CVE-2019-16710)

ReadXWDImage in coders/xwd.c in the XWD image parsing component of
ImageMagick 7.0.8-41 Q16 allows attackers to cause a denial-of-service
(divide-by-zero error) by crafting an XWD image file in which the
header indicates neither LSB first nor MSB first. (CVE-2019-11472)

ImageMagick 7.0.8-34 has a memory leak vulnerability in the
WriteDPXImage function in coders/dpx.c. (CVE-2019-12975)

The cineon parsing component in ImageMagick 7.0.8-26 Q16 allows
attackers to cause a denial-of-service (uncontrolled resource
consumption) by crafting a Cineon image with an incorrect claimed
image size. This occurs because ReadCINImage in coders/cin.c lacks a
check for insufficient image data in a file. (CVE-2019-11470)

An off-by-one read vulnerability was discovered in ImageMagick before
version 7.0.7-28 in the formatIPTCfromBuffer function in
coders/meta.c. A local attacker may use this flaw to read beyond the
end of the buffer or to crash the program. (CVE-2019-10131)

WriteEPTImage in coders/ept.c in ImageMagick 7.0.7-25 Q16 allows
remote attackers to cause a denial of service (MagickCore/memory.c
double free and application crash) or possibly have unspecified other
impact via a crafted file. (CVE-2018-8804)

ImageMagick 7.0.7-12 Q16, a CPU exhaustion vulnerability was found in
the function ReadDDSInfo in coders/dds.c, which allows attackers to
cause a denial of service. (CVE-2017-1000476)

In ImageMagick before 7.0.8-8, a NULL pointer dereference exists in
the CheckEventLogging function in MagickCore/log.c. (CVE-2018-16328)

ImageMagick 7.0.8-34 has a 'use of uninitialized value' vulnerability
in the SyncImageSettings function in MagickCore/image.c. This is
related to AcquireImage in magick/image.c. (CVE-2019-12979)

ImageMagick 7.0.8-54 Q16 allows Division by Zero in
RemoveDuplicateLayers in MagickCore/layer.c. (CVE-2019-13454)

In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer over-read in
the function WritePNGImage of coders/png.c, related to
Magick_png_write_raw_profile and LocaleNCompare. (CVE-2019-19949)

In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer overflow in
the function WriteSGIImage of coders/sgi.c. (CVE-2019-19948)

In ImageMagick 7.0.7-20 Q16 x86_64, a memory leak vulnerability was
found in the function ReadDCMImage in coders/dcm.c, which allows
attackers to cause a denial of service via a crafted DCM image file.
(CVE-2018-11656)

In coders/bmp.c in ImageMagick before 7.0.8-16, an input file can
result in an infinite loop and hang, with high CPU and memory
consumption. Remote attackers could leverage this vulnerability to
cause a denial of service via a crafted file. (CVE-2018-20467)

ImageMagick 7.0.8-50 Q16 has a heap-based buffer overflow at
MagickCore/statistic.c in EvaluateImages because of mishandling rows.
(CVE-2019-13307)

ImageMagick 7.0.8-50 Q16 has a stack-based buffer overflow at
coders/pnm.c in WritePNMImage because of off-by-one errors.
(CVE-2019-13306)

ImageMagick 7.0.8-50 Q16 has a stack-based buffer overflow at
coders/pnm.c in WritePNMImage because of a misplaced strncpy and an
off-by-one error. (CVE-2019-13305)

ImageMagick 7.0.8-50 Q16 has a stack-based buffer overflow at
coders/pnm.c in WritePNMImage because of a misplaced assignment.
(CVE-2019-13304)

ImageMagick 7.0.8-50 Q16 has memory leaks in AcquireMagickMemory
because of an AnnotateImage error. (CVE-2019-13301)

ImageMagick 7.0.8-50 Q16 has a heap-based buffer overflow at
MagickCore/statistic.c in EvaluateImages because of mishandling
columns. (CVE-2019-13300)

ImageMagick 7.0.8-50 Q16 has memory leaks at AcquireMagickMemory
because of mishandling the NoSuchImage error in CLIListOperatorImages
in MagickWand/operation.c. (CVE-2019-13309)

In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer over-read in
the function WriteTIFFImage of coders/tiff.c, which allows an attacker
to cause a denial of service or possibly information disclosure via a
crafted image file. (CVE-2019-11597)

In ImageMagick 7.0.8-3 Q16, ReadBMPImage and WriteBMPImage in
coders/bmp.c allow attackers to cause an out of bounds write via a
crafted file. (CVE-2018-12599)

A NULL pointer dereference in the function ReadPANGOImage in
coders/pango.c and the function ReadVIDImage in coders/vid.c in
ImageMagick 7.0.8-34 allows remote attackers to cause a denial of
service via a crafted image. (CVE-2019-12974)

In ImageMagick 7.0.7-29 and earlier, a memory leak in the
formatIPTCfromBuffer function in coders/meta.c was found.
(CVE-2018-16750)

ImageMagick version 7.0.7-28 contains a memory leak in WriteTIFFImage
in coders/tiff.c. (CVE-2018-10804)

ImageMagick version 7.0.7-28 contains a memory leak in ReadYCBCRImage
in coders/ycbcr.c. (CVE-2018-10805)

ImageMagick 7.0.7-26 Q16 has excessive iteration in the DecodeLabImage
and EncodeLabImage functions (coders/tiff.c), which results in a hang
(tens of minutes) with a tiny PoC file. Remote attackers could
leverage this vulnerability to cause a denial of service via a crafted
tiff file. (CVE-2018-9133)

In ImageMagick before 7.0.8-25, a memory leak exists in WriteDIBImage
in coders/dib.c. (CVE-2019-7398)

ImageMagick 7.0.8-50 Q16 has a heap-based buffer over-read at
MagickCore/threshold.c in AdaptiveThresholdImage because a width of
zero is mishandled. (CVE-2019-13295)

ImageMagick 7.0.8-50 Q16 has a heap-based buffer over-read at
MagickCore/threshold.c in AdaptiveThresholdImage because a height of
zero is mishandled. (CVE-2019-13297)

In ImageMagick 7.0.7-28, there is an infinite loop in the
ReadOneMNGImage function of the coders/png.c file. Remote attackers
could leverage this vulnerability to cause a denial of service via a
crafted mng file. (CVE-2018-10177)

In ImageMagick 7.0.8-3 Q16, ReadDIBImage and WriteDIBImage in
coders/dib.c allow attackers to cause an out of bounds write via a
crafted file. (CVE-2018-12600)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1391.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update php-pecl-imagick' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pecl-imagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"php-pecl-imagick-3.4.4-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pecl-imagick-debuginfo-3.4.4-1.8.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pecl-imagick / php-pecl-imagick-debuginfo");
}
