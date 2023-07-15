#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104285);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-14517",
    "CVE-2017-14518",
    "CVE-2017-14519",
    "CVE-2017-14520",
    "CVE-2017-14617",
    "CVE-2017-14929",
    "CVE-2017-14975",
    "CVE-2017-14976",
    "CVE-2017-14977"
  );

  script_name(english:"EulerOS 2.0 SP2 : poppler (EulerOS-SA-2017-1260)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the poppler packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - In Poppler 0.59.0, a NULL Pointer Dereference exists in
    the XRef::parseEntry() function in XRef.cc via a
    crafted PDF document.(CVE-2017-14517)

  - In Poppler 0.59.0, a floating point exception exists in
    the isImageInterpolationRequired() function in
    Splash.cc via a crafted PDF document.(CVE-2017-14518)

  - In Poppler 0.59.0, memory corruption occurs in a call
    to Object::streamGetChar in Object.h after a repeating
    series of Gfx::display, Gfx::go, Gfx::execOp,
    Gfx::opShowText, and Gfx::doShowText calls (aka a
    Gfx.cc infinite loop).(CVE-2017-14519)

  - In Poppler 0.59.0, a floating point exception occurs in
    Splash::scaleImageYuXd() in Splash.cc, which may lead
    to a potential attack when handling malicious PDF
    files.(CVE-2017-14520)

  - In Poppler 0.59.0, a floating point exception occurs in
    the ImageStream class in Stream.cc, which may lead to a
    potential attack when handling malicious PDF
    files.(CVE-2017-14617)

  - In Poppler 0.59.0, memory corruption occurs in a call
    to Object::dictLookup() in Object.h after a repeating
    series of Gfx::display, Gfx::go, Gfx::execOp,
    Gfx::opFill, Gfx::doPatternFill,
    Gfx::doTilingPatternFill and Gfx::drawForm calls (aka a
    Gfx.cc infinite loop), a different vulnerability than
    CVE-2017-14519.(CVE-2017-14929)

  - The FoFiTrueType::getCFFBlock function in
    FoFiTrueType.cc in Poppler 0.59.0 has a NULL pointer
    dereference vulnerability due to lack of validation of
    a table pointer, which allows an attacker to launch a
    denial of service attack.(CVE-2017-14977)

  - The FoFiType1C::convertToType0 function in
    FoFiType1C.cc in Poppler 0.59.0 has a heap-based buffer
    over-read vulnerability if an out-of-bounds font
    dictionary index is encountered, which allows an
    attacker to launch a denial of service
    attack.(CVE-2017-14976)

  - The FoFiType1C::convertToType0 function in
    FoFiType1C.cc in Poppler 0.59.0 has a NULL pointer
    dereference vulnerability because a data structure is
    not initialized, which allows an attacker to launch a
    denial of service attack.(CVE-2017-14975)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1260
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81277526");
  script_set_attribute(attribute:"solution", value:
"Update the affected poppler packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/01");

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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["poppler-0.26.5-17.h9",
        "poppler-glib-0.26.5-17.h9",
        "poppler-qt-0.26.5-17.h9",
        "poppler-utils-0.26.5-17.h9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler");
}
