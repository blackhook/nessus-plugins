#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139136);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2018-10177",
    "CVE-2018-10804",
    "CVE-2018-16749",
    "CVE-2019-12974",
    "CVE-2019-12976",
    "CVE-2019-12977",
    "CVE-2019-12978",
    "CVE-2019-12979",
    "CVE-2019-13295",
    "CVE-2019-13297",
    "CVE-2019-13300",
    "CVE-2019-13304",
    "CVE-2019-13305",
    "CVE-2019-13306",
    "CVE-2019-13307",
    "CVE-2019-13308",
    "CVE-2019-13309",
    "CVE-2019-13310",
    "CVE-2019-13311",
    "CVE-2019-13391",
    "CVE-2019-7395",
    "CVE-2019-7396",
    "CVE-2019-7398"
  );

  script_name(english:"EulerOS 2.0 SP8 : ImageMagick (EulerOS-SA-2020-1806)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ImageMagick packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In ImageMagick 7.0.7-29 and earlier, a missing NULL
    check in ReadOneJNGImage in coders/png.c allows an
    attacker to cause a denial of service (WriteBlob
    assertion failure and application exit) via a crafted
    file.(CVE-2018-16749)

  - A NULL pointer dereference in the function
    ReadPANGOImage in coders/pango.c and the function
    ReadVIDImage in coders/vid.c in ImageMagick 7.0.8-34
    allows remote attackers to cause a denial of service
    via a crafted image.(CVE-2019-12974)

  - ImageMagick 7.0.8-34 has a memory leak in the
    ReadPCLImage function in coders/pcl.c.(CVE-2019-12976)

  - ImageMagick 7.0.8-50 Q16 has memory leaks at
    AcquireMagickMemory because of mishandling the
    NoSuchImage error in CLIListOperatorImages in
    MagickWand/operation.c.(CVE-2019-13309)

  - ImageMagick 7.0.8-50 Q16 has memory leaks at
    AcquireMagickMemory because of an error in
    MagickWand/mogrify.c.(CVE-2019-13310)

  - ImageMagick 7.0.8-50 Q16 has memory leaks at
    AcquireMagickMemory because of a wand/mogrify.c
    error.(CVE-2019-13311)

  - In ImageMagick 7.0.7-28, there is an infinite loop in
    the ReadOneMNGImage function of the coders/png.c file.
    Remote attackers could leverage this vulnerability to
    cause a denial of service via a crafted mng
    file.(CVE-2018-10177)

  - ImageMagick version 7.0.7-28 contains a memory leak in
    WriteTIFFImage in coders/tiff.c.(CVE-2018-10804)

  - In ImageMagick before 7.0.8-25, a memory leak exists in
    WritePSDChannel in coders/psd.c.(CVE-2019-7395)

  - In ImageMagick before 7.0.8-25, a memory leak exists in
    ReadSIXELImage in coders/sixel.c.(CVE-2019-7396)

  - In ImageMagick before 7.0.8-25, a memory leak exists in
    WriteDIBImage in coders/dib.c.(CVE-2019-7398)

  - ImageMagick 7.0.8-34 has a 'use of uninitialized value'
    vulnerability in the WriteJP2Image function in
    coders/jp2.c.(CVE-2019-12977)

  - ImageMagick 7.0.8-34 has a 'use of uninitialized value'
    vulnerability in the ReadPANGOImage function in
    coders/pango.c.(CVE-2019-12978)

  - ImageMagick 7.0.8-34 has a 'use of uninitialized value'
    vulnerability in the SyncImageSettings function in
    MagickCore/image.c. This is related to AcquireImage in
    magick/image.c.(CVE-2019-12979)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer
    over-read at MagickCore/threshold.c in
    AdaptiveThresholdImage because a width of zero is
    mishandled.(CVE-2019-13295)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer
    over-read at MagickCore/threshold.c in
    AdaptiveThresholdImage because a height of zero is
    mishandled.(CVE-2019-13297)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer
    overflow at MagickCore/statistic.c in EvaluateImages
    because of mishandling columns.(CVE-2019-13300)

  - ImageMagick 7.0.8-50 Q16 has a stack-based buffer
    overflow at coders/pnm.c in WritePNMImage because of a
    misplaced assignment.(CVE-2019-13304)

  - ImageMagick 7.0.8-50 Q16 has a stack-based buffer
    overflow at coders/pnm.c in WritePNMImage because of a
    misplaced strncpy and an off-by-one
    error.(CVE-2019-13305)

  - ImageMagick 7.0.8-50 Q16 has a stack-based buffer
    overflow at coders/pnm.c in WritePNMImage because of
    off-by-one errors.(CVE-2019-13306)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer
    overflow at MagickCore/statistic.c in EvaluateImages
    because of mishandling rows.(CVE-2019-13307)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer
    overflow in MagickCore/fourier.c in
    ComplexImage.(CVE-2019-13308)

  - In ImageMagick 7.0.8-50 Q16, ComplexImages in
    MagickCore/fourier.c has a heap-based buffer over-read
    because of incorrect calls to
    GetCacheViewVirtualPixels.(CVE-2019-13391)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1806
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df34806a");
  script_set_attribute(attribute:"solution", value:
"Update the affected ImageMagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/30");

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

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["ImageMagick-6.9.9.38-3.h15.eulerosv2r8",
        "ImageMagick-c++-6.9.9.38-3.h15.eulerosv2r8",
        "ImageMagick-libs-6.9.9.38-3.h15.eulerosv2r8",
        "ImageMagick-perl-6.9.9.38-3.h15.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
