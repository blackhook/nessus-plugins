#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0227. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132506);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2016-3186",
    "CVE-2018-7456",
    "CVE-2018-8905",
    "CVE-2018-10779",
    "CVE-2018-10963",
    "CVE-2018-12900",
    "CVE-2018-17100",
    "CVE-2018-17101",
    "CVE-2018-18557",
    "CVE-2018-18661"
  );
  script_bugtraq_id(
    85744,
    104089,
    105370,
    105749,
    105762,
    107658
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : libtiff Multiple Vulnerabilities (NS-SA-2019-0227)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has libtiff packages installed that are affected
by multiple vulnerabilities:

  - Buffer overflow in the readextension function in
    gif2tiff.c in LibTIFF 4.0.6 allows remote attackers to
    cause a denial of service (application crash) via a
    crafted GIF file. (CVE-2016-3186)

  - Heap-based buffer overflow in the
    cpSeparateBufToContigBuf function in tiffcp.c in LibTIFF
    4.0.9 allows remote attackers to cause a denial of
    service (crash) or possibly have unspecified other
    impact via a crafted TIFF file. (CVE-2018-12900)

  - The TIFFWriteDirectorySec() function in tif_dirwrite.c
    in LibTIFF through 4.0.9 allows remote attackers to
    cause a denial of service (assertion failure and
    application crash) via a crafted file, a different
    vulnerability than CVE-2017-13726. (CVE-2018-10963)

  - TIFFWriteScanline in tif_write.c in LibTIFF 3.8.2 has a
    heap-based buffer over-read, as demonstrated by
    bmp2tiff. (CVE-2018-10779)

  - In LibTIFF 4.0.9, a heap-based buffer overflow occurs in
    the function LZWDecodeCompat in tif_lzw.c via a crafted
    TIFF file, as demonstrated by tiff2ps. (CVE-2018-8905)

  - A NULL Pointer Dereference occurs in the function
    TIFFPrintDirectory in tif_print.c in LibTIFF 4.0.9 when
    using the tiffinfo tool to print crafted TIFF
    information, a different vulnerability than
    CVE-2017-18013. (This affects an earlier part of the
    TIFFPrintDirectory function that was not addressed by
    the CVE-2017-18013 patch.) (CVE-2018-7456)

  - An issue was discovered in LibTIFF 4.0.9. There is a
    int32 overflow in multiply_ms in tools/ppm2tiff.c, which
    can cause a denial of service (crash) or possibly have
    unspecified other impact via a crafted image file.
    (CVE-2018-17100)

  - An issue was discovered in LibTIFF 4.0.9. There are two
    out-of-bounds writes in cpTags in tools/tiff2bw.c and
    tools/pal2rgb.c, which can cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted image file. (CVE-2018-17101)

  - LibTIFF 4.0.9 (with JBIG enabled) decodes arbitrarily-
    sized JBIG into a buffer, ignoring the buffer size,
    which leads to a tif_jbig.c JBIGDecode out-of-bounds
    write. (CVE-2018-18557)

  - An issue was discovered in LibTIFF 4.0.9. There is a
    NULL pointer dereference in the function LZWDecode in
    the file tif_lzw.c. (CVE-2018-18661)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0227");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libtiff packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8905");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "libtiff-4.0.3-32.el7",
    "libtiff-debuginfo-4.0.3-32.el7",
    "libtiff-devel-4.0.3-32.el7",
    "libtiff-static-4.0.3-32.el7",
    "libtiff-tools-4.0.3-32.el7"
  ],
  "CGSL MAIN 5.05": [
    "libtiff-4.0.3-32.el7",
    "libtiff-debuginfo-4.0.3-32.el7",
    "libtiff-devel-4.0.3-32.el7",
    "libtiff-static-4.0.3-32.el7",
    "libtiff-tools-4.0.3-32.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
