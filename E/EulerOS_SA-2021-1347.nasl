#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146719);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_cve_id(
    "CVE-2017-14927",
    "CVE-2017-9865",
    "CVE-2018-21009",
    "CVE-2019-12293",
    "CVE-2019-12360",
    "CVE-2019-9631"
  );

  script_name(english:"EulerOS 2.0 SP2 : poppler (EulerOS-SA-2021-1347)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the poppler packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Poppler 0.74.0 has a heap-based buffer over-read in the
    CairoRescaleBox.cc downsample_row_box_filter
    function.(CVE-2019-9631)

  - In Poppler through 0.76.1, there is a heap-based buffer
    over-read in JPXStream::init in JPEG2000Stream.cc via
    data with inconsistent heights or
    widths.(CVE-2019-12293)

  - A stack-based buffer over-read exists in
    FoFiTrueType::dumpString in fofi/FoFiTrueType.cc in
    Xpdf 4.01.01. It can, for example, be triggered by
    sending crafted TrueType data in a PDF document to the
    pdftops tool. It might allow an attacker to cause
    Denial of Service or leak memory data into dump
    content.(CVE-2019-12360)

  - Poppler before 0.66.0 has an integer overflow in
    Parser::makeStream in Parser.cc.(CVE-2018-21009)

  - In Poppler 0.59.0, a NULL Pointer Dereference exists in
    the SplashOutputDev::type3D0() function in
    SplashOutputDev.cc via a crafted PDF
    document.(CVE-2017-14927)

  - The function GfxImageColorMap::getGray in GfxState.cc
    in Poppler 0.54.0 allows remote attackers to cause a
    denial of service (stack-based buffer over-read and
    application crash) via a crafted PDF document, related
    to missing color-map validation in
    ImageOutputDev.cc.(CVE-2017-9865)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1347
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f2eb2d3");
  script_set_attribute(attribute:"solution", value:
"Update the affected poppler packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["poppler-0.26.5-17.h23",
        "poppler-glib-0.26.5-17.h23",
        "poppler-qt-0.26.5-17.h23",
        "poppler-utils-0.26.5-17.h23"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler");
}
