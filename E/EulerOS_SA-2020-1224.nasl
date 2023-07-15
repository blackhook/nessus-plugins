#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134513);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2014-9745",
    "CVE-2014-9747",
    "CVE-2015-9290",
    "CVE-2015-9381",
    "CVE-2015-9382",
    "CVE-2015-9383",
    "CVE-2016-10244"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : freetype (EulerOS-SA-2020-1224)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the freetype package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - The FreeType engine is a free and portable font
    rendering engine, developed to provide advanced font
    support for a variety of platforms and environments.
    FreeType is a library which can open and manages font
    files as well as efficiently load, hint and render
    individual glyphs. FreeType is not a font server or a
    complete text-rendering library. Security Fix(es):The
    t42_parse_encoding function in type42/t42parse.c in
    FreeType before 2.5.4 does not properly update the
    current position for immediates-only mode, which allows
    remote attackers to cause a denial of service (infinite
    loop) via a Type42 font.(CVE-2014-9747)In Sudo before
    1.8.28, an attacker with access to a Runas ALL sudoer
    account can bypass certain policy blacklists and
    session PAM modules, and can cause incorrect logging,
    by invoking sudo with a crafted user ID. For example,
    this allows bypass of !root configuration, and USER=
    logging, for a 'sudo -u \#$((0xffffffff))'
    command.(CVE-2015-9383)FreeType before 2.6.1 has a
    buffer over-read in skip_comment in psaux/psobjs.c
    because ps_parser_skip_PS_token is mishandled in an
    FT_New_Memory_Face operation.(CVE-2015-9382)FreeType
    before 2.6.1 has a heap-based buffer over-read in
    T1_Get_Private_Dict in
    type1/t1parse.c.(CVE-2015-9381)In FreeType before
    2.6.1, a buffer over-read occurs in type1/t1parse.c on
    function T1_Get_Private_Dict where there is no check
    that the new values of cur and limit are sensible
    before going to Again.(CVE-2015-9290)The parse_encoding
    function in type1/t1load.c in FreeType before 2.5.3
    allows remote attackers to cause a denial of service
    (infinite loop) via a 'broken number-with-base' in a
    Postscript stream, as demonstrated by
    8#garbage.(CVE-2014-9745)The parse_charstrings function
    in type1/t1load.c in FreeType 2 before 2.7 does not
    ensure that a font contains a glyph name, which allows
    remote attackers to cause a denial of service
    (heap-based buffer over-read) or possibly have
    unspecified other impact via a crafted
    file.(CVE-2016-10244)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1224
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f7eb85c");
  script_set_attribute(attribute:"solution", value:
"Update the affected freetype packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["freetype-2.4.11-15.h9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype");
}
