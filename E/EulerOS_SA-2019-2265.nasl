#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130727);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-10092",
    "CVE-2016-10266",
    "CVE-2016-10267",
    "CVE-2016-10268",
    "CVE-2016-10269",
    "CVE-2016-10270",
    "CVE-2016-10272",
    "CVE-2016-10371",
    "CVE-2016-3186",
    "CVE-2016-3622",
    "CVE-2016-9273",
    "CVE-2016-9538",
    "CVE-2016-9539",
    "CVE-2017-10688",
    "CVE-2017-12944",
    "CVE-2017-13726",
    "CVE-2017-13727",
    "CVE-2017-7592",
    "CVE-2017-7593",
    "CVE-2017-7594",
    "CVE-2017-7595",
    "CVE-2017-7596",
    "CVE-2017-7597",
    "CVE-2017-7598",
    "CVE-2017-7599",
    "CVE-2017-7600",
    "CVE-2017-7601",
    "CVE-2017-7602",
    "CVE-2017-9403",
    "CVE-2017-9936",
    "CVE-2018-7456",
    "CVE-2018-8905"
  );

  script_name(english:"EulerOS 2.0 SP3 : libtiff (EulerOS-SA-2019-2265)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libtiff packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - There is a reachable assertion abort in the function
    TIFFWriteDirectoryTagSubifd() in LibTIFF 4.0.8, related
    to tif_dirwrite.c and a SubIFD tag. A crafted input
    will lead to a remote denial of service
    attack.(CVE-2017-13727)

  - The putagreytile function in tif_getimage.c in LibTIFF
    4.0.7 has a left-shift undefined behavior issue, which
    might allow remote attackers to cause a denial of
    service (application crash) or possibly have
    unspecified other impact via a crafted
    image.(CVE-2017-7592)

  - tif_read.c in LibTIFF 4.0.7 does not ensure that
    tif_rawdata is properly initialized, which might allow
    remote attackers to obtain sensitive information from
    process memory via a crafted image.(CVE-2017-7593)

  - The OJPEGReadHeaderInfoSecTablesDcTable function in
    tif_ojpeg.c in LibTIFF 4.0.7 allows remote attackers to
    cause a denial of service (memory leak) via a crafted
    image.(CVE-2017-7594)

  - The JPEGSetupEncode function in tiff_jpeg.c in LibTIFF
    4.0.7 allows remote attackers to cause a denial of
    service (divide-by-zero error and application crash)
    via a crafted image.(CVE-2017-7595)

  - LibTIFF 4.0.7 has an 'outside the range of
    representable values of type float' undefined behavior
    issue, which might allow remote attackers to cause a
    denial of service (application crash) or possibly have
    unspecified other impact via a crafted
    image.(CVE-2017-7596)

  - tif_dirread.c in LibTIFF 4.0.7 has an 'outside the
    range of representable values of type float' undefined
    behavior issue, which might allow remote attackers to
    cause a denial of service (application crash) or
    possibly have unspecified other impact via a crafted
    image.(CVE-2017-7597)

  - LibTIFF 4.0.7 has an 'outside the range of
    representable values of type short' undefined behavior
    issue, which might allow remote attackers to cause a
    denial of service (application crash) or possibly have
    unspecified other impact via a crafted
    image.(CVE-2017-7599)

  - LibTIFF 4.0.7 has an 'outside the range of
    representable values of type unsigned char' undefined
    behavior issue, which might allow remote attackers to
    cause a denial of service (application crash) or
    possibly have unspecified other impact via a crafted
    image.(CVE-2017-7600)

  - tif_dirread.c in LibTIFF 4.0.7 might allow remote
    attackers to cause a denial of service (divide-by-zero
    error and application crash) via a crafted
    image.(CVE-2017-7598)

  - LibTIFF 4.0.7 has a 'shift exponent too large for
    64-bit type long' undefined behavior issue, which might
    allow remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted image.(CVE-2017-7601)

  - LibTIFF 4.0.7 has a signed integer overflow, which
    might allow remote attackers to cause a denial of
    service (application crash) or possibly have
    unspecified other impact via a crafted
    image.(CVE-2017-7602)

  - In LibTIFF 4.0.7, a memory leak vulnerability was found
    in the function TIFFReadDirEntryLong8Array in
    tif_dirread.c, which allows attackers to cause a denial
    of service via a crafted file.(CVE-2017-9403)

  - In LibTIFF 4.0.8, there is a memory leak in tif_jbig.c.
    A crafted TIFF document can lead to a memory leak
    resulting in a remote denial of service
    attack.(CVE-2017-9936)

  - Heap-based buffer overflow in the
    readContigStripsIntoBuffer function in tif_unix.c in
    LibTIFF 4.0.7 allows remote attackers to have
    unspecified impact via a crafted image.(CVE-2016-10092)

  - LibTIFF 4.0.7 allows remote attackers to cause a denial
    of service (heap-based buffer overflow) or possibly
    have unspecified other impact via a crafted TIFF image,
    related to 'WRITE of size 2048' and
    libtiff/tif_next.c:64:9.(CVE-2016-10272)

  - LibTIFF 4.0.7 allows remote attackers to cause a denial
    of service (divide-by-zero error and application crash)
    via a crafted TIFF image, related to
    libtiff/tif_read.c:351:22.(CVE-2016-10266)

  - LibTIFF 4.0.7 allows remote attackers to cause a denial
    of service (divide-by-zero error and application crash)
    via a crafted TIFF image, related to
    libtiff/tif_ojpeg.c:816:8.(CVE-2016-10267)

  - tools/tiffcp.c in LibTIFF 4.0.7 allows remote attackers
    to cause a denial of service (integer underflow and
    heap-based buffer under-read) or possibly have
    unspecified other impact via a crafted TIFF image,
    related to 'READ of size 78490' and
    libtiff/tif_unix.c:115:23.(CVE-2016-10268)

  - LibTIFF 4.0.7 allows remote attackers to cause a denial
    of service (heap-based buffer over-read) or possibly
    have unspecified other impact via a crafted TIFF image,
    related to 'READ of size 512' and
    libtiff/tif_unix.c:340:2.(CVE-2016-10269)

  - LibTIFF 4.0.7 allows remote attackers to cause a denial
    of service (heap-based buffer over-read) or possibly
    have unspecified other impact via a crafted TIFF image,
    related to 'READ of size 8' and
    libtiff/tif_read.c:523:22.(CVE-2016-10270)

  - The TIFFWriteDirectoryTagCheckedRational function in
    tif_dirwrite.c in LibTIFF 4.0.6 allows remote attackers
    to cause a denial of service (assertion failure and
    application exit) via a crafted TIFF
    file.(CVE-2016-10371)

  - The fpAcc function in tif_predict.c in the tiff2rgba
    tool in LibTIFF 4.0.6 and earlier allows remote
    attackers to cause a denial of service (divide-by-zero
    error) via a crafted TIFF image.(CVE-2016-3622)

  - tiffsplit in libtiff 4.0.6 allows remote attackers to
    cause a denial of service (out-of-bounds read) via a
    crafted file, related to changing td_nstrips in
    TIFF_STRIPCHOP mode.(CVE-2016-9273)

  - The TIFFReadDirEntryArray function in tif_read.c in
    LibTIFF 4.0.8 mishandles memory allocation for short
    files, which allows remote attackers to cause a denial
    of service (allocation failure and application crash)
    in the TIFFFetchStripThing function in tif_dirread.c
    during a tiff2pdf invocation.(CVE-2017-12944)

  - There is a reachable assertion abort in the function
    TIFFWriteDirectorySec() in LibTIFF 4.0.8, related to
    tif_dirwrite.c and a SubIFD tag. A crafted input will
    lead to a remote denial of service
    attack.(CVE-2017-13726)

  - tools/tiffcrop.c in libtiff 4.0.6 reads an undefined
    buffer in readContigStripsIntoBuffer() because of a
    uint16 integer overflow. Reported as MSVR
    35100.(CVE-2016-9538)

  - tools/tiffcrop.c in libtiff 4.0.6 has an out-of-bounds
    read in readContigTilesIntoBuffer(). Reported as MSVR
    35092.(CVE-2016-9539)

  - In LibTIFF 4.0.8, there is a assertion abort in the
    TIFFWriteDirectoryTagCheckedLong8Array function in
    tif_dirwrite.c. A crafted input will lead to a remote
    denial of service attack.(CVE-2017-10688)

  - Buffer overflow in the readextension function in
    gif2tiff.c in LibTIFF 4.0.6 allows remote attackers to
    cause a denial of service (application crash) via a
    crafted GIF file.(CVE-2016-3186)

  - A NULL Pointer Dereference occurs in the function
    TIFFPrintDirectory in tif_print.c in LibTIFF 4.0.9 when
    using the tiffinfo tool to print crafted TIFF
    information, a different vulnerability than
    CVE-2017-18013. (This affects an earlier part of the
    TIFFPrintDirectory function that was not addressed by
    the CVE-2017-18013 patch.)(CVE-2018-7456)

  - In LibTIFF 4.0.9, a heap-based buffer overflow occurs
    in the function LZWDecodeCompat in tif_lzw.c via a
    crafted TIFF file, as demonstrated by
    tiff2ps.(CVE-2018-8905)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2265
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4354c43e");
  script_set_attribute(attribute:"solution", value:
"Update the affected libtiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libtiff-devel");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libtiff-4.0.3-27.h14",
        "libtiff-devel-4.0.3-27.h14"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff");
}
