##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162289);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/15");

  script_cve_id(
    "CVE-2022-0561",
    "CVE-2022-0562",
    "CVE-2022-0865",
    "CVE-2022-0891",
    "CVE-2022-0907",
    "CVE-2022-0908",
    "CVE-2022-0909",
    "CVE-2022-0924",
    "CVE-2022-22844"
  );

  script_name(english:"EulerOS 2.0 SP9 : libtiff (EulerOS-SA-2022-1869)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libtiff package installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

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

  - LibTIFF 4.3.0 has an out-of-bounds read in _TIFFmemcpy in tif_unix.c in certain situations involving a
    custom tag and 0x0200 as the second word of the DE field. (CVE-2022-22844)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1869
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db0f9c51");
  script_set_attribute(attribute:"solution", value:
"Update the affected libtiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0891");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libtiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "libtiff-4.1.0-1.h1.r6.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff");
}
