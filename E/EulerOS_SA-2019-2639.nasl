#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132174);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-6887",
    "CVE-2014-0158",
    "CVE-2016-10505",
    "CVE-2016-7445",
    "CVE-2017-14040",
    "CVE-2017-14041",
    "CVE-2017-17479"
  );
  script_bugtraq_id(
    64140
  );

  script_name(english:"EulerOS 2.0 SP3 : openjpeg (EulerOS-SA-2019-2639)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openjpeg package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A stack-based buffer overflow was discovered in the
    pgxtoimage function in bin/jp2/convert.c in OpenJPEG
    2.2.0. The vulnerability causes an out-of-bounds write,
    which may lead to remote denial of service or possibly
    remote code execution.(CVE-2017-14041)

  - An invalid write access was discovered in
    bin/jp2/convert.c in OpenJPEG 2.2.0, triggering a crash
    in the tgatoimage function. The vulnerability may lead
    to remote denial of service or possibly unspecified
    other impact.(CVE-2017-14040)

  - convert.c in OpenJPEG before 2.1.2 allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via vectors
    involving the variable s.(CVE-2016-7445)

  - Heap-based buffer overflow in the JPEG2000 image tile
    decoder in OpenJPEG before 1.5.2 allows remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted file because of incorrect j2k_decode,
    j2k_read_eoc, and tcd_decode_tile interaction, a
    related issue to CVE-2013-6045. NOTE: this is not a
    duplicate of CVE-2013-1447, because the scope of
    CVE-2013-1447 was specifically defined in
    http://openwall.com/lists/oss-security/2013/12/04/6 as
    only 'null pointer dereferences, division by zero, and
    anything that would just fit as DoS.'(CVE-2014-0158)

  - In OpenJPEG 2.3.0, a stack-based buffer overflow was
    discovered in the pgxtoimage function in
    jpwl/convert.c. The vulnerability causes an
    out-of-bounds write, which may lead to remote denial of
    service or possibly remote code
    execution.(CVE-2017-17479)

  - NULL pointer dereference vulnerabilities in the
    imagetopnm function in convert.c, sycc444_to_rgb
    function in color.c, color_esycc_to_rgb function in
    color.c, and sycc422_to_rgb function in color.c in
    OpenJPEG before 2.2.0 allow remote attackers to cause a
    denial of service (application crash) via crafted j2k
    files.(CVE-2016-10505)

  - OpenJPEG 1.5.1 allows remote attackers to cause a
    denial of service via unspecified vectors that trigger
    NULL pointer dereferences, division-by-zero, and other
    errors.(CVE-2013-6887)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2639
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9efb114");
  script_set_attribute(attribute:"solution", value:
"Update the affected openjpeg packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openjpeg-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openjpeg-libs-1.5.1-16.h2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg");
}
