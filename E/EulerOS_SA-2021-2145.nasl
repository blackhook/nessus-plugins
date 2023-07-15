#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151389);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id(
    "CVE-2016-9297",
    "CVE-2017-11335",
    "CVE-2017-9404",
    "CVE-2018-15209",
    "CVE-2018-16335",
    "CVE-2018-5784"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : libtiff (EulerOS-SA-2021-2145)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libtiff package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The TIFFFetchNormalTag function in LibTiff 4.0.6 allows
    remote attackers to cause a denial of service
    (out-of-bounds read) via crafted TIFF_SETGET_C16ASCII
    or TIFF_SETGET_C32_ASCII tag values.(CVE-2016-9297)

  - There is a heap based buffer overflow in
    tools/tiff2pdf.c of LibTIFF 4.0.8 via a
    PlanarConfig=Contig image, which causes a more than one
    hundred bytes out-of-bounds write (related to the
    ZIPDecode function in tif_zip.c). A crafted input may
    lead to a remote denial of service attack or an
    arbitrary code execution attack.(CVE-2017-11335)

  - In LibTIFF 4.0.7, a memory leak vulnerability was found
    in the function OJPEGReadHeaderInfoSecTablesQTable in
    tif_ojpeg.c, which allows attackers to cause a denial
    of service via a crafted file.(CVE-2017-9404)

  - ChopUpSingleUncompressedStrip in tif_dirread.c in
    LibTIFF 4.0.9 allows remote attackers to cause a denial
    of service (heap-based buffer overflow and application
    crash) or possibly have unspecified other impact via a
    crafted TIFF file, as demonstrated by
    tiff2pdf.(CVE-2018-15209)

  - newoffsets handling in ChopUpSingleUncompressedStrip in
    tif_dirread.c in LibTIFF 4.0.9 allows remote attackers
    to cause a denial of service (heap-based buffer
    overflow and application crash) or possibly have
    unspecified other impact via a crafted TIFF file, as
    demonstrated by tiff2pdf. This is a different
    vulnerability than CVE-2018-15209.(CVE-2018-16335)

  - In LibTIFF 4.0.9, there is an uncontrolled resource
    consumption in the TIFFSetDirectory function of
    tif_dir.c. Remote attackers could leverage this
    vulnerability to cause a denial of service via a
    crafted tif file. This occurs because the declared
    number of directory entries is not validated against
    the actual number of directory entries.(CVE-2018-5784)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2145
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05c3a8d3");
  script_set_attribute(attribute:"solution", value:
"Update the affected libtiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libtiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libtiff-4.0.3-27.h26.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
