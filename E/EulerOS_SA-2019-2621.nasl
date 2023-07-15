#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132156);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-3623",
    "CVE-2016-3624",
    "CVE-2016-5102",
    "CVE-2016-5318",
    "CVE-2016-5321",
    "CVE-2016-5323",
    "CVE-2017-16232",
    "CVE-2017-9147",
    "CVE-2018-10963",
    "CVE-2018-12900",
    "CVE-2018-17100",
    "CVE-2018-17101",
    "CVE-2018-18557",
    "CVE-2018-18661",
    "CVE-2018-19210",
    "CVE-2019-14973",
    "CVE-2019-17546",
    "CVE-2019-6128",
    "CVE-2019-7663"
  );

  script_name(english:"EulerOS 2.0 SP3 : libtiff (EulerOS-SA-2019-2621)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libtiff packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - ** DISPUTED ** LibTIFF 4.0.8 has multiple memory leak
    vulnerabilities, which allow attackers to cause a
    denial of service (memory consumption), as demonstrated
    by tif_open.c, tif_lzw.c, and tif_aux.c. NOTE: Third
    parties were unable to reproduce the
    issue.(CVE-2017-16232)

  - _TIFFCheckMalloc and _TIFFCheckRealloc in tif_aux.c in
    LibTIFF through 4.0.10 mishandle Integer Overflow
    checks because they rely on compiler behavior that is
    undefined by the applicable C standards. This can, for
    example, lead to an application crash.(CVE-2019-14973)

  - An Invalid Address dereference was discovered in
    TIFFWriteDirectoryTagTransferfunction in
    libtiff/tif_dirwrite.c in LibTIFF 4.0.10, affecting the
    cpSeparateBufToContigBuf function in tiffcp.c. Remote
    attackers could leverage this vulnerability to cause a
    denial-of-service via a crafted tiff file. This is
    different from CVE-2018-12900.(CVE-2019-7663)

  - An issue was discovered in LibTIFF 4.0.9. There are two
    out-of-bounds writes in cpTags in tools/tiff2bw.c and
    tools/pal2rgb.c, which can cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted image file.(CVE-2018-17101)

  - An issue was discovered in LibTIFF 4.0.9. There is a
    int32 overflow in multiply_ms in tools/ppm2tiff.c,
    which can cause a denial of service (crash) or possibly
    have unspecified other impact via a crafted image
    file.(CVE-2018-17100)

  - An issue was discovered in LibTIFF 4.0.9. There is a
    NULL pointer dereference in the function LZWDecode in
    the file tif_lzw.c.(CVE-2018-18661)

  - Buffer overflow in the readgifimage function in
    gif2tiff.c in the gif2tiff tool in LibTIFF 4.0.6 allows
    remote attackers to cause a denial of service
    (segmentation fault) via a crafted gif
    file.(CVE-2016-5102)

  - Heap-based buffer overflow in the
    cpSeparateBufToContigBuf function in tiffcp.c in
    LibTIFF 4.0.9 allows remote attackers to cause a denial
    of service (crash) or possibly have unspecified other
    impact via a crafted TIFF file.(CVE-2018-12900)

  - In LibTIFF 4.0.9, there is a NULL pointer dereference
    in the TIFFWriteDirectorySec function in tif_dirwrite.c
    that will lead to a denial of service attack, as
    demonstrated by tiffset.(CVE-2018-19210)

  - LibTIFF 4.0.7 has an invalid read in the _TIFFVGetField
    function in tif_dir.c, which might allow remote
    attackers to cause a denial of service (crash) via a
    crafted TIFF file.(CVE-2017-9147)

  - LibTIFF 4.0.9 (with JBIG enabled) decodes
    arbitrarily-sized JBIG into a buffer, ignoring the
    buffer size, which leads to a tif_jbig.c JBIGDecode
    out-of-bounds write.(CVE-2018-18557)

  - Stack-based buffer overflow in the _TIFFVGetField
    function in libtiff 4.0.6 and earlier allows remote
    attackers to crash the application via a crafted
    tiff.(CVE-2016-5318)

  - The _TIFFFax3fillruns function in libtiff before 4.0.6
    allows remote attackers to cause a denial of service
    (divide-by-zero error and application crash) via a
    crafted Tiff image.(CVE-2016-5323)

  - The cvtClump function in the rgb2ycbcr tool in LibTIFF
    4.0.6 and earlier allows remote attackers to cause a
    denial of service (out-of-bounds write) by setting the
    '-v' option to -1.(CVE-2016-3624)

  - The DumpModeDecode function in libtiff 4.0.6 and
    earlier allows attackers to cause a denial of service
    (invalid read and crash) via a crafted tiff
    image.(CVE-2016-5321)

  - The rgb2ycbcr tool in LibTIFF 4.0.6 and earlier allows
    remote attackers to cause a denial of service
    (divide-by-zero) by setting the (1) v or (2) h
    parameter to 0.(CVE-2016-3623)

  - The TIFFFdOpen function in tif_unix.c in LibTIFF 4.0.10
    has a memory leak, as demonstrated by
    pal2rgb.(CVE-2019-6128)

  - The TIFFWriteDirectorySec() function in tif_dirwrite.c
    in LibTIFF through 4.0.9 allows remote attackers to
    cause a denial of service (assertion failure and
    application crash) via a crafted file, a different
    vulnerability than CVE-2017-13726.(CVE-2018-10963)

  - tif_getimage.c in LibTIFF through 4.0.10, as used in
    GDAL through 3.0.1 and other products, has an integer
    overflow that potentially causes a heap-based buffer
    overflow via a crafted RGBA image, related to a
    'Negative-size-param' condition.(CVE-2019-17546)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2621
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f75a97ab");
  script_set_attribute(attribute:"solution", value:
"Update the affected libtiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

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

pkgs = ["libtiff-4.0.3-27.h18",
        "libtiff-devel-4.0.3-27.h18"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff");
}
