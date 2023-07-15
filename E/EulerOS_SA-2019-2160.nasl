#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130869);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2016-10145",
    "CVE-2016-10252",
    "CVE-2016-7539",
    "CVE-2017-13139",
    "CVE-2017-13143",
    "CVE-2017-13146",
    "CVE-2017-15033",
    "CVE-2017-17499",
    "CVE-2017-5507",
    "CVE-2017-5509",
    "CVE-2017-5510",
    "CVE-2018-12600",
    "CVE-2018-16323",
    "CVE-2018-16328",
    "CVE-2018-16329",
    "CVE-2018-20467",
    "CVE-2018-8804"
  );

  script_name(english:"EulerOS 2.0 SP5 : ImageMagick (EulerOS-SA-2019-2160)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ImageMagick packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - ImageMagick is an image display and manipulation tool
    for the X Window System. ImageMagick can read and write
    JPEG, TIFF, PNM, GIF,and Photo CD image formats. It can
    resize, rotate, sharpen, color reduce, or add special
    effects to an image, and when finished you can either
    save the completed work in the original format or a
    different one. ImageMagick also includes command line
    programs for creating animated or transparent .gifs,
    creating composite images, creating thumbnail images,
    and more.ImageMagick is one of your choices if you need
    a program to manipulate and display images. If you want
    to develop your own applications which use ImageMagick
    code or APIs, you need to install ImageMagick-devel as
    well.Security Fix(es):In ImageMagick before 7.0.8-8, a
    NULL pointer dereference exists in the
    GetMagickProperty function in
    MagickCore/property.c.(CVE-2018-16329)ImageMagick
    before 6.9.9-24 and 7.x before 7.0.7-12 has a
    use-after-free in Magick::Image::read in
    Magick++/lib/Image.cpp.(CVE-2017-17499)In ImageMagick
    before 6.9.8-5 and 7.x before 7.0.5-6, there is a
    memory leak in the ReadMATImage function in
    coders/mat.c.(CVE-2017-13146)In ImageMagick before
    6.9.7-6 and 7.x before 7.0.4-6, the ReadMATImage
    function in coders/mat.c uses uninitialized data, which
    might allow remote attackers to obtain sensitive
    information from process memory.(CVE-2017-13143)In
    ImageMagick before 6.9.9-0 and 7.x before 7.0.6-1, the
    ReadOneMNGImage function in coders/png.c has an
    out-of-bounds read with the MNG CLIP
    chunk.(CVE-2017-13139)coders/psd.c in ImageMagick
    allows remote attackers to have unspecified impact via
    a crafted PSD file, which triggers an out-of-bounds
    write.(CVE-2017-5510)coders/psd.c in ImageMagick allows
    remote attackers to have unspecified impact via a
    crafted PSD file, which triggers an out-of-bounds
    write.(CVE-2017-5509)Memory leak in coders/mpc.c in
    ImageMagick before 6.9.7-4 and 7.x before 7.0.4-4
    allows remote attackers to cause a denial of service
    (memory consumption) via vectors involving a pixel
    cache.(CVE-2017-5507)Memory leak in the IsOptionMember
    function in MagickCore/option.c in ImageMagick before
    6.9.2-2, as used in ODR-PadEnc and other products,
    allows attackers to trigger memory
    consumption.(CVE-2016-10252)Off-by-one error in
    coders/wpg.c in ImageMagick allows remote attackers to
    have unspecified impact via vectors related to a string
    copy.(CVE-2016-10145)Memory leak in
    AcquireVirtualMemory in ImageMagick before 7 allows
    remote attackers to cause a denial of service (memory
    consumption) via unspecified vectors.(CVE-2016-7539)In
    coders/bmp.c in ImageMagick before 7.0.8-16, an input
    file can result in an infinite loop and hang, with high
    CPU and memory consumption. Remote attackers could
    leverage this vulnerability to cause a denial of
    service via a crafted file.(CVE-2018-20467)In
    ImageMagick before 7.0.8-8, a NULL pointer dereference
    exists in the CheckEventLogging function in
    MagickCore/log.c.(CVE-2018-16328)ReadXBMImage in
    coders/xbm.c in ImageMagick before 7.0.8-9 leaves data
    uninitialized when processing an XBM file that has a
    negative pixel value. If the affected code is used as a
    library loaded into a process that includes sensitive
    information, that information sometimes can be leaked
    via the image data.(CVE-2018-16323)WriteEPTImage in
    coders/ept.c in ImageMagick 7.0.7-25 Q16 allows remote
    attackers to cause a denial of service
    (MagickCore/memory.c double free and application crash)
    or possibly have unspecified other impact via a crafted
    file.(CVE-2018-8804)In ImageMagick 7.0.8-3 Q16,
    ReadDIBImage and WriteDIBImage in coders/dib.c allow
    attackers to cause an out of bounds write via a crafted
    file.(CVE-2018-12600)ImageMagick version 7.0.7-2
    contains a memory leak in ReadYUVImage in
    coders/yuv.c.(CVE-2017-15033)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2160
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65bf07e6");
  script_set_attribute(attribute:"solution", value:
"Update the affected ImageMagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16329");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ImageMagick-6.9.9.38-3.h11.eulerosv2r7",
        "ImageMagick-c++-6.9.9.38-3.h11.eulerosv2r7",
        "ImageMagick-libs-6.9.9.38-3.h11.eulerosv2r7",
        "ImageMagick-perl-6.9.9.38-3.h11.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
