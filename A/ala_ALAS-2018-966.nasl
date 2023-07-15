#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-966.
#

include("compat.inc");

if (description)
{
  script_id(107237);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-11102", "CVE-2017-11139", "CVE-2017-11140", "CVE-2017-11636", "CVE-2017-11637", "CVE-2017-11641", "CVE-2017-11643", "CVE-2017-13147", "CVE-2017-16353", "CVE-2017-16669", "CVE-2017-17782", "CVE-2017-17783", "CVE-2017-17912", "CVE-2017-17913", "CVE-2017-17915", "CVE-2018-5685");
  script_xref(name:"ALAS", value:"2018-966");

  script_name(english:"Amazon Linux AMI : GraphicsMagick (ALAS-2018-966)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Memory information disclosure in DescribeImage function in
magick/describe.c

GraphicsMagick is vulnerable to a memory information disclosure
vulnerability found in the DescribeImage function of the
magick/describe.c file, because of a heap-based buffer over-read. The
portion of the code containing the vulnerability is responsible for
printing the IPTC Profile information contained in the image. This
vulnerability can be triggered with a specially crafted MIFF file.
There is an out-of-bounds buffer dereference because certain
increments are never checked. (CVE-2017-16353 )

GraphicsMagick 1.3.26 has double free vulnerabilities in the
ReadOneJNGImage() function in coders/png.c (CVE-2017-11139)

In GraphicsMagick there is a stack-based buffer over-read in
WriteWEBPImage in coders/webp.c, related to an incompatibility with
libwebp versions, 0.5.0 and later, that use a different structure
type. (CVE-2017-17913)

In GraphicsMagick 1.3.27, there is an infinite loop and application
hang in the ReadBMPImage function (coders/bmp.c). Remote attackers
could leverage this vulnerability to cause a denial of service via an
image file with a crafted bit-field mask value. (CVE-2018-5685)

The ReadJPEGImage function in coders/jpeg.c in GraphicsMagick 1.3.26
creates a pixel cache before a successful read of a scanline, which
allows remote attackers to cause a denial of service (resource
consumption) via crafted JPEG files. (CVE-2017-11140)

In GraphicsMagick 1.3.26, an allocation failure vulnerability was
found in the function ReadMNGImage in coders/png.c when a small MNG
file has a MEND chunk with a large length value. (CVE-2017-13147)

GraphicsMagick 1.3.26 has a heap overflow in the WriteCMYKImage()
function in coders/cmyk.c when processing multiple frames that have
non-identical widths. (CVE-2017-11643)

GraphicsMagick 1.3.26 has a Memory Leak in the PersistCache function
in magick/pixel_cache.c during writing of Magick Persistent Cache
(MPC) files. (CVE-2017-11641)

In GraphicsMagick there is a heap-based buffer over-read in
ReadMNGImage in coders/png.c, related to accessing one byte before
testing whether a limit has been reached. (CVE-2017-17915)

In GraphicsMagick 1.3.27a, there is a buffer over-read in
ReadPALMImage in coders/palm.c when QuantumDepth is 8.
(CVE-2017-17783)

In GraphicsMagick 1.3.27a, there is a heap-based buffer over-read in
ReadOneJNGImage in coders/png.c, related to oFFs chunk allocation.
(CVE-2017-17782)

coders/wpg.c in GraphicsMagick 1.3.26 allows remote attackers to cause
a denial of service (heap-based buffer overflow and application crash)
or possibly have unspecified other impact via a crafted file, related
to the AcquireCacheNexus function in magick/pixel_cache.c.
(CVE-2017-16669)

In GraphicsMagick there is a heap-based buffer over-read in
ReadNewsProfile in coders/tiff.c, in which LocaleNCompare reads heap
data beyond the allocated region. (CVE-2017-17912)

The ReadOneJNGImage function in coders/png.c in GraphicsMagick 1.3.26
allows remote attackers to cause a denial of service (application
crash) during JNG reading via a zero-length color_image data
structure. (CVE-2017-11102)

GraphicsMagick 1.3.26 has a NULL pointer dereference in the
WritePCLImage() function in coders/pcl.c during writes of monochrome
images. (CVE-2017-11637)

GraphicsMagick 1.3.26 has a heap overflow in the WriteRGBImage()
function in coders/rgb.c when processing multiple frames that have
non-identical widths. (CVE-2017-11636)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-966.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update GraphicsMagick' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:GraphicsMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"GraphicsMagick-1.3.28-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-c++-1.3.28-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-c++-devel-1.3.28-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-debuginfo-1.3.28-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-devel-1.3.28-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-doc-1.3.28-1.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"GraphicsMagick-perl-1.3.28-1.12.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-c++ / GraphicsMagick-c++-devel / etc");
}
