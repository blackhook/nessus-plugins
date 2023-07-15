#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101849);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-8959",
    "CVE-2016-5010",
    "CVE-2016-7522",
    "CVE-2016-7532",
    "CVE-2016-7535",
    "CVE-2016-7537",
    "CVE-2016-7538"
  );

  script_name(english:"EulerOS 2.0 SP1 : ImageMagick (EulerOS-SA-2017-1116)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ImageMagick packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - coders/dds.c in ImageMagick before 6.9.0-4 Beta allows
    remote attackers to cause a denial of service (CPU
    consumption) via a crafted DDS file.i1/4^CVE-2015-8959i1/4%0

  - coders/tiff.c in ImageMagick before 6.9.5-3 allows
    remote attackers to cause a denial of service
    (out-of-bounds read) via a crafted TIFF
    file.i1/4^CVE-2016-5010i1/4%0

  - The ReadPSDImage function in MagickCore/locale.c in
    ImageMagick allows remote attackers to cause a denial
    of service (out-of-bounds read) via a crafted PSD
    file.i1/4^CVE-2016-7522i1/4%0

  - coders/psd.c in ImageMagick allows remote attackers to
    cause a denial of service (out-of-bounds read) via a
    crafted PSD file.i1/4^CVE-2016-7532i1/4%0

  - coders/psd.c in ImageMagick allows remote attackers to
    cause a denial of service (out-of-bounds write) via a
    crafted PSD file.i1/4^CVE-2016-7535i1/4%0

  - MagickCore/memory.c in ImageMagick allows remote
    attackers to cause a denial of service (out-of-bounds
    access) via a crafted PDB file.i1/4^CVE-2016-7537i1/4%0

  - coders/psd.c in ImageMagick allows remote attackers to
    cause a denial of service (out-of-bounds write) via a
    crafted file.i1/4^CVE-2016-7538i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1116
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7c17a74");
  script_set_attribute(attribute:"solution", value:
"Update the affected ImageMagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/21");

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

pkgs = ["ImageMagick-6.7.8.9-15.h7",
        "ImageMagick-c++-6.7.8.9-15.h7",
        "ImageMagick-perl-6.7.8.9-15.h7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
