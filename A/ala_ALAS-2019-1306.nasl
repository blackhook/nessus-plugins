#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1306.
#

include("compat.inc");

if (description)
{
  script_id(129796);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/15  9:43:15");

  script_cve_id("CVE-2016-3186", "CVE-2018-10779", "CVE-2018-10963", "CVE-2018-12900", "CVE-2018-17100", "CVE-2018-17101", "CVE-2018-18557", "CVE-2018-18661", "CVE-2018-7456", "CVE-2018-8905");
  script_xref(name:"ALAS", value:"2019-1306");

  script_name(english:"Amazon Linux AMI : libtiff (ALAS-2019-1306)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflow in the readextension function in gif2tiff.c in LibTIFF
4.0.6 allows remote attackers to cause a denial of service
(application crash) via a crafted GIF file.(CVE-2016-3186)

An integer overflow has been discovered in libtiff in
TIFFSetupStrips:tif_write.c, which could lead to a heap-based buffer
overflow in TIFFWriteScanline:tif_write.c. An attacker may use this
vulnerability to corrupt memory or cause Denial of
Service.(CVE-2018-10779)

The TIFFWriteDirectorySec() function in tif_dirwrite.c in LibTIFF
through 4.0.9 allows remote attackers to cause a denial of service
(assertion failure and application crash) via a crafted file, a
different vulnerability than CVE-2017-13726 .(CVE-2018-10963)

Heap-based buffer overflow in the cpSeparateBufToContigBuf function in
tiffcp.c in LibTIFF 4.0.9 allows remote attackers to cause a denial of
service (crash) or possibly have unspecified other impact via a
crafted TIFF file.(CVE-2018-12900)

An issue was discovered in LibTIFF 4.0.9. There is a int32 overflow in
multiply_ms in tools/ppm2tiff.c, which can cause a denial of service
(crash) or possibly have unspecified other impact via a crafted image
file.(CVE-2018-17100)

An issue was discovered in LibTIFF 4.0.9. There are two out-of-bounds
writes in cpTags in tools/tiff2bw.c and tools/pal2rgb.c, which can
cause a denial of service (application crash) or possibly have
unspecified other impact via a crafted image file.(CVE-2018-17101)

LibTIFF 4.0.9 (with JBIG enabled) decodes arbitrarily-sized JBIG into
a buffer, ignoring the buffer size, which leads to a tif_jbig.c
JBIGDecode out-of-bounds write.(CVE-2018-18557)

An issue was discovered in LibTIFF 4.0.9. There is a NULL pointer
dereference in the function LZWDecode in the file
tif_lzw.c.(CVE-2018-18661)

A NULL pointer Dereference occurs in the function TIFFPrintDirectory
in tif_print.c in LibTIFF 4.0.9 when using the tiffinfo tool to print
crafted TIFF information, a different vulnerability than
CVE-2017-18013 . (This affects an earlier part of the
TIFFPrintDirectory function that was not addressed by the
CVE-2017-18013 patch.)(CVE-2018-7456)

In LibTIFF 4.0.9, a heap-based buffer overflow occurs in the function
LZWDecodeCompat in tif_lzw.c via a crafted TIFF file, as demonstrated
by tiff2ps.(CVE-2018-8905)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1306.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libtiff' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"libtiff-4.0.3-32.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-debuginfo-4.0.3-32.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-devel-4.0.3-32.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtiff-static-4.0.3-32.34.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-debuginfo / libtiff-devel / libtiff-static");
}
