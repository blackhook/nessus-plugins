#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99889);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id(
    "CVE-2014-8127",
    "CVE-2014-8129",
    "CVE-2014-8130",
    "CVE-2014-9330",
    "CVE-2014-9655",
    "CVE-2015-1547",
    "CVE-2015-7554",
    "CVE-2015-8665",
    "CVE-2015-8668",
    "CVE-2015-8683",
    "CVE-2015-8781",
    "CVE-2015-8784",
    "CVE-2016-3632",
    "CVE-2016-3945",
    "CVE-2016-3990",
    "CVE-2016-3991",
    "CVE-2016-5320",
    "CVE-2016-5652",
    "CVE-2016-9533",
    "CVE-2016-9534",
    "CVE-2016-9535",
    "CVE-2016-9536",
    "CVE-2016-9537",
    "CVE-2016-9540"
  );
  script_bugtraq_id(
    71789,
    72323,
    72352,
    72353,
    73438,
    73441
  );

  script_name(english:"EulerOS 2.0 SP1 : compat-libtiff3 (EulerOS-SA-2017-1044)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the compat-libtiff3 package installed,
the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - The (1) putcontig8bitYCbCr21tile function in
    tif_getimage.c or (2) NeXTDecode function in tif_next.c
    in LibTIFF allows remote attackers to cause a denial of
    service (uninitialized memory access) via a crafted
    TIFF image, as demonstrated by libtiff-cvs-1.tif and
    libtiff-cvs-2.tif.(CVE-2014-8127,CVE-2014-8129,CVE-2014
    -8130,CVE-2014-9655)

  - A flaw was discovered in the bmp2tiff utility. By
    tricking a user into processing a specially crafted
    file, a remote attacker could exploit this flaw to
    cause a crash or memory corruption and, possibly,
    execute arbitrary code with the privileges of the user
    running the libtiff
    tool.(CVE-2014-9330,CVE-2015-7554,CVE-2015-8668,CVE-201
    5-8665,CVE-2015-8781,CVE-2016-3632,CVE-2016-3945,CVE-20
    16-3990,CVE-2016-3991,CVE-2016-5320,CVE-2016-5652,CVE-2
    015-8683)

  - tools/tiffcp.c in libtiff has an out-of-bounds write on
    tiled images with odd tile width versus image width.
    Reported as MSVR 35103, aka 'cpStripToTile
    heap-buffer-overflow.'(CVE-2016-9540)

  - tif_predict.h and tif_predict.c in libtiff have
    assertions that can lead to assertion failures in debug
    mode, or buffer overflows in release mode, when dealing
    with unusual tile size like YCbCr with subsampling.
    Reported as MSVR 35105, aka 'Predictor
    heap-buffer-overflow.'(CVE-2016-9535,CVE-2016-9533,CVE-
    2016-9534,CVE-2016-9536,CVE-2016-9537)

  - The NeXTDecode function in tif_next.c in LibTIFF allows
    remote attackers to cause a denial of service
    (uninitialized memory access) via a crafted TIFF image,
    as demonstrated by libtiff5.tif.(CVE-2015-1547)

  - The NeXTDecode function in tif_next.c in LibTIFF allows
    remote attackers to cause a denial of service
    (out-of-bounds write) via a crafted TIFF image, as
    demonstrated by libtiff5.tif.(CVE-2015-8784)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1044
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11ee83d6");
  script_set_attribute(attribute:"solution", value:
"Update the affected compat-libtiff3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:compat-libtiff3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["compat-libtiff3-3.9.4-11.h19"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-libtiff3");
}
