#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104282);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-14139",
    "CVE-2017-14224",
    "CVE-2017-14682",
    "CVE-2017-15016",
    "CVE-2017-15017",
    "CVE-2017-15033",
    "CVE-2017-15281"
  );

  script_name(english:"EulerOS 2.0 SP1 : ImageMagick (EulerOS-SA-2017-1257)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ImageMagick packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A heap-based buffer overflow in WritePCXImage in
    coders/pcx.c in ImageMagick 7.0.6-8 Q16 allows remote
    attackers to cause a denial of service or code
    execution via a crafted file.(CVE-2017-14224)

  - GetNextToken in MagickCore/token.c in ImageMagick 7.0.6
    allows remote attackers to cause a denial of service
    (heap-based buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    SVG document, a different vulnerability than
    CVE-2017-10928.(CVE-2017-14682)

  - ImageMagick version 7.0.7-2 contains a memory leak in
    ReadYUVImage in coders/yuv.c.(CVE-2017-15033)

  - ImageMagick 7.0.7-0 Q16 has a NULL pointer dereference
    vulnerability in ReadEnhMetaFile in
    coders/emf.c.(CVE-2017-15016)

  - ImageMagick 7.0.7-0 Q16 has a NULL pointer dereference
    vulnerability in ReadOneMNGImage in
    coders/png.c.(CVE-2017-15017)

  - ImageMagick 7.0.6-2 has a memory leak vulnerability in
    WriteMSLImage in coders/msl.c.(CVE-2017-14139)

  - ReadPSDImage in coders/psd.c in ImageMagick 7.0.7-6
    allows remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact via a crafted file, related to 'Conditional jump
    or move depends on uninitialised
    value(s).'(CVE-2017-15281)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1257
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bd66db9");
  script_set_attribute(attribute:"solution", value:
"Update the affected ImageMagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ImageMagick-perl");
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

pkgs = ["ImageMagick-6.7.8.9-15.h14",
        "ImageMagick-c++-6.7.8.9-15.h14",
        "ImageMagick-perl-6.7.8.9-15.h14"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
