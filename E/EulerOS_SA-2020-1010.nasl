#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132603);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2018-14551",
    "CVE-2018-15607",
    "CVE-2018-16328",
    "CVE-2018-18544",
    "CVE-2019-11470"
  );

  script_name(english:"EulerOS 2.0 SP8 : ImageMagick (EulerOS-SA-2020-1010)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ImageMagick packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The cineon parsing component in ImageMagick 7.0.8-26
    Q16 allows attackers to cause a denial-of-service
    (uncontrolled resource consumption) by crafting a
    Cineon image with an incorrect claimed image size. This
    occurs because ReadCINImage in coders/cin.c lacks a
    check for insufficient image data in a
    file.(CVE-2019-11470)

  - In ImageMagick before 7.0.8-8, a NULL pointer
    dereference exists in the CheckEventLogging function in
    MagickCore/log.c.(CVE-2018-16328)

  - In ImageMagick 7.0.8-11 Q16, a tiny input file 0x50
    0x36 0x36 0x36 0x36 0x4c 0x36 0x38 0x36 0x36 0x36 0x36
    0x36 0x36 0x1f 0x35 0x50 0x00 can result in a hang of
    several minutes during which CPU and memory resources
    are consumed until ultimately an attempted large memory
    allocation fails. Remote attackers could leverage this
    vulnerability to cause a denial of service via a
    crafted file.(CVE-2018-15607)

  - The ReadMATImageV4 function in coders/mat.c in
    ImageMagick 7.0.8-7 uses an uninitialized variable,
    leading to memory corruption.(CVE-2018-14551)

  - There is a memory leak in the function WriteMSLImage of
    coders/msl.c in ImageMagick 7.0.8-13 Q16, and the
    function ProcessMSLScript of coders/msl.c in
    GraphicsMagick before 1.3.31.(CVE-2018-18544)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?100a3061");
  script_set_attribute(attribute:"solution", value:
"Update the affected ImageMagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/02");

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

pkgs = ["ImageMagick-6.9.9.38-3.h11.eulerosv2r8",
        "ImageMagick-c++-6.9.9.38-3.h11.eulerosv2r8",
        "ImageMagick-libs-6.9.9.38-3.h11.eulerosv2r8",
        "ImageMagick-perl-6.9.9.38-3.h11.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
