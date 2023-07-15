#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149134);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/04");

  script_cve_id(
    "CVE-2017-11533",
    "CVE-2017-13768",
    "CVE-2017-9501",
    "CVE-2019-14981",
    "CVE-2019-15139",
    "CVE-2019-15140",
    "CVE-2019-16708",
    "CVE-2019-16709",
    "CVE-2019-16710",
    "CVE-2019-16711",
    "CVE-2019-16713",
    "CVE-2019-19948",
    "CVE-2019-19949",
    "CVE-2021-20176"
  );

  script_name(english:"EulerOS 2.0 SP3 : ImageMagick (EulerOS-SA-2021-1802)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ImageMagick packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A divide-by-zero flaw was found in ImageMagick
    6.9.11-57 and 7.0.10-57 in gem.c. This flaw allows an
    attacker who submits a crafted file that is processed
    by ImageMagick to trigger undefined behavior through a
    division by zero. The highest threat from this
    vulnerability is to system
    availability.(CVE-2021-20176)

  - coders/mat.c in ImageMagick 7.0.8-43 Q16 allows remote
    attackers to cause a denial of service (use-after-free
    and application crash) or possibly have unspecified
    other impact by crafting a Matlab image file that is
    mishandled in ReadImage in
    MagickCore/constitute.c.(CVE-2019-15140)

  - ImageMagick 7.0.8-35 has a memory leak in coders/dot.c,
    as demonstrated by AcquireMagickMemory in
    MagickCore/memory.c.(CVE-2019-16710)

  - ImageMagick 7.0.8-35 has a memory leak in coders/dps.c,
    as demonstrated by XCreateImage.(CVE-2019-16709)

  - ImageMagick 7.0.8-35 has a memory leak in
    magick/xwindow.c, related to
    XCreateImage.(CVE-2019-16708)

  - ImageMagick 7.0.8-40 has a memory leak in
    Huffman2DEncodeImage in coders/ps2.c.(CVE-2019-16711)

  - ImageMagick 7.0.8-43 has a memory leak in coders/dot.c,
    as demonstrated by PingImage in
    MagickCore/constitute.c.(CVE-2019-16713)

  - In ImageMagick 7.0.5-7 Q16, an assertion failure was
    found in the function LockSemaphoreInfo, which allows
    attackers to cause a denial of service via a crafted
    file.(CVE-2017-9501)

  - In ImageMagick 7.0.8-43 Q16, there is a heap-based
    buffer overflow in the function WriteSGIImage of
    coders/sgi.c.(CVE-2019-19948)

  - In ImageMagick 7.0.8-43 Q16, there is a heap-based
    buffer over-read in the function WritePNGImage of
    coders/png.c, related to Magick_png_write_raw_profile
    and LocaleNCompare.(CVE-2019-19949)

  - In ImageMagick 7.x before 7.0.8-41 and 6.x before
    6.9.10-41, there is a divide-by-zero vulnerability in
    the MeanShiftImage function. It allows an attacker to
    cause a denial of service by sending a crafted
    file.(CVE-2019-14981)

  - Null Pointer Dereference in the IdentifyImage function
    in MagickCore/identify.c in ImageMagick through
    7.0.6-10 allows an attacker to perform denial of
    service by sending a crafted image
    file.(CVE-2017-13768)

  - The XWD image (X Window System window dumping file)
    parsing component in ImageMagick 7.0.8-41 Q16 allows
    attackers to cause a denial-of-service (application
    crash resulting from an out-of-bounds Read) in
    ReadXWDImage in coders/xwd.c by crafting a corrupted
    XWD image file, a different vulnerability than
    CVE-2019-11472.(CVE-2019-15139)

  - When ImageMagick 7.0.6-1 processes a crafted file in
    convert, it can lead to a heap-based buffer over-read
    in the WriteUILImage() function in
    coders/uil.c.(CVE-2017-11533)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1802
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f267d37c");
  script_set_attribute(attribute:"solution", value:
"Update the affected ImageMagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

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

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ImageMagick-6.9.9.38-1.h14",
        "ImageMagick-c++-6.9.9.38-1.h14",
        "ImageMagick-libs-6.9.9.38-1.h14",
        "ImageMagick-perl-6.9.9.38-1.h14"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
