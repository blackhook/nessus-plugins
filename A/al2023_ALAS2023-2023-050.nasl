#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-050.
##

include('compat.inc');

if (description)
{
  script_id(173149);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2022-0561",
    "CVE-2022-0562",
    "CVE-2022-0865",
    "CVE-2022-0891",
    "CVE-2022-0907",
    "CVE-2022-0908",
    "CVE-2022-0909",
    "CVE-2022-0924",
    "CVE-2022-1056",
    "CVE-2022-1354",
    "CVE-2022-1355",
    "CVE-2022-1622",
    "CVE-2022-1623",
    "CVE-2022-2056",
    "CVE-2022-2057",
    "CVE-2022-2058",
    "CVE-2022-2869",
    "CVE-2022-3970",
    "CVE-2022-22844",
    "CVE-2022-34526"
  );

  script_name(english:"Amazon Linux 2023 : libtiff, libtiff-devel, libtiff-static (ALAS2023-2023-050)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-050 advisory.

  - Null source pointer passed as an argument to memcpy() function within TIFFFetchStripThing() in
    tif_dirread.c in libtiff versions from 3.9.0 to 4.3.0 could lead to Denial of Service via crafted TIFF
    file. For users that compile libtiff from sources, the fix is available with commit eecb0712.
    (CVE-2022-0561)

  - Null source pointer passed as an argument to memcpy() function within TIFFReadDirectory() in tif_dirread.c
    in libtiff versions from 4.0 to 4.3.0 could lead to Denial of Service via crafted TIFF file. For users
    that compile libtiff from sources, a fix is available with commit 561599c. (CVE-2022-0562)

  - Reachable Assertion in tiffcp in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted
    tiff file. For users that compile libtiff from sources, the fix is available with commit 5e180045.
    (CVE-2022-0865)

  - A heap buffer overflow in ExtractImageSection function in tiffcrop.c in libtiff library Version 4.3.0
    allows attacker to trigger unsafe or out of bounds memory access via crafted TIFF image file which could
    result into application crash, potential information disclosure or any other context-dependent impact
    (CVE-2022-0891)

  - Unchecked Return Value to NULL Pointer Dereference in tiffcrop in libtiff 4.3.0 allows attackers to cause
    a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is
    available with commit f2b656e2. (CVE-2022-0907)

  - Null source pointer passed as an argument to memcpy() function within TIFFFetchNormalTag () in
    tif_dirread.c in libtiff versions up to 4.3.0 could lead to Denial of Service via crafted TIFF file.
    (CVE-2022-0908)

  - Divide By Zero error in tiffcrop in libtiff 4.3.0 allows attackers to cause a denial-of-service via a
    crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f8d0f9aa.
    (CVE-2022-0909)

  - Out-of-bounds Read error in tiffcp in libtiff 4.3.0 allows attackers to cause a denial-of-service via a
    crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 408976c4.
    (CVE-2022-0924)

  - Out-of-bounds Read error in tiffcrop in libtiff 4.3.0 allows attackers to cause a denial-of-service via a
    crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 46dc8fcd.
    (CVE-2022-1056)

  - A heap buffer overflow flaw was found in Libtiffs' tiffinfo.c in TIFFReadRawDataStriped() function. This
    flaw allows an attacker to pass a crafted TIFF file to the tiffinfo tool, triggering a heap buffer
    overflow issue and causing a crash that leads to a denial of service. (CVE-2022-1354)

  - A stack buffer overflow flaw was found in Libtiffs' tiffcp.c in main() function. This flaw allows an
    attacker to pass a crafted TIFF file to the tiffcp tool, triggering a stack buffer overflow issue,
    possibly corrupting the memory, and causing a crash that leads to a denial of service. (CVE-2022-1355)

  - LibTIFF master branch has an out-of-bounds read in LZWDecode in libtiff/tif_lzw.c:619, allowing attackers
    to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix
    is available with commit b4e79bfa. (CVE-2022-1622)

  - LibTIFF master branch has an out-of-bounds read in LZWDecode in libtiff/tif_lzw.c:624, allowing attackers
    to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix
    is available with commit b4e79bfa. (CVE-2022-1623)

  - Divide By Zero error in tiffcrop in libtiff 4.4.0 allows attackers to cause a denial-of-service via a
    crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f3a5e010.
    (CVE-2022-2056, CVE-2022-2057, CVE-2022-2058)

  - LibTIFF 4.3.0 has an out-of-bounds read in _TIFFmemcpy in tif_unix.c in certain situations involving a
    custom tag and 0x0200 as the second word of the DE field. (CVE-2022-22844)

  - libtiff's tiffcrop tool has a uint32_t underflow which leads to out of bounds read and write in the
    extractContigSamples8bits routine. An attacker who supplies a crafted file to tiffcrop could trigger this
    flaw, most likely by tricking a user into opening the crafted file with tiffcrop. Triggering this flaw
    could cause a crash or potentially further exploitation. (CVE-2022-2869)

  - A stack overflow was discovered in the _TIFFVGetField function of Tiffsplit v4.4.0. This vulnerability
    allows attackers to cause a Denial of Service (DoS) via a crafted TIFF file parsed by the tiffsplit or
    tiffcrop utilities. (CVE-2022-34526)

  - A vulnerability was found in LibTIFF. It has been classified as critical. This affects the function
    TIFFReadRGBATileExt of the file libtiff/tif_getimage.c. The manipulation leads to integer overflow. It is
    possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.
    The name of the patch is 227500897dfb07fb7d27f7aa570050e62617e3be. It is recommended to apply a patch to
    fix this issue. The identifier VDB-213549 was assigned to this vulnerability. (CVE-2022-3970)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-050.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0561.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0562.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0865.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0891.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0907.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0908.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0909.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0924.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1056.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1354.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1355.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1622.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1623.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2056.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2057.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2058.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22844.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2869.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-34526.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3970.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update libtiff --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0891");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3970");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'libtiff-4.4.0-4.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-4.4.0-4.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-4.4.0-4.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-debuginfo-4.4.0-4.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-debuginfo-4.4.0-4.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-debuginfo-4.4.0-4.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-debugsource-4.4.0-4.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-debugsource-4.4.0-4.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-debugsource-4.4.0-4.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-devel-4.4.0-4.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-devel-4.4.0-4.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-devel-4.4.0-4.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-static-4.4.0-4.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-static-4.4.0-4.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-static-4.4.0-4.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-tools-4.4.0-4.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-tools-4.4.0-4.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-tools-4.4.0-4.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-tools-debuginfo-4.4.0-4.amzn2023.0.3', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-tools-debuginfo-4.4.0-4.amzn2023.0.3', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-tools-debuginfo-4.4.0-4.amzn2023.0.3', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-debuginfo / libtiff-debugsource / etc");
}