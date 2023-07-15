#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170849);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");

  script_cve_id(
    "CVE-2021-23437",
    "CVE-2021-25290",
    "CVE-2021-28675",
    "CVE-2021-28676",
    "CVE-2021-28677",
    "CVE-2021-34552",
    "CVE-2022-22815",
    "CVE-2022-22816",
    "CVE-2022-22817"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : python-pillow (EulerOS-SA-2023-1288)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-pillow package installed, the EulerOS Virtualization installation on the remote
host is affected by the following vulnerabilities :

  - The package pillow 5.2.0 and before 8.3.2 are vulnerable to Regular Expression Denial of Service (ReDoS)
    via the getrgb function. (CVE-2021-23437)

  - An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is a negative-offset memcpy with an
    invalid size. (CVE-2021-25290)

  - An issue was discovered in Pillow before 8.2.0. PSDImagePlugin.PsdImageFile lacked a sanity check on the
    number of input layers relative to the size of the data block. This could lead to a DoS on Image.open
    prior to Image.load. (CVE-2021-28675)

  - An issue was discovered in Pillow before 8.2.0. For FLI data, FliDecode did not properly check that the
    block advance was non-zero, potentially leading to an infinite loop on load. (CVE-2021-28676)

  - An issue was discovered in Pillow before 8.2.0. For EPS data, the readline implementation used in
    EPSImageFile has to deal with any combination of \r and \n as line endings. It used an accidentally
    quadratic method of accumulating lines while looking for a line ending. A malicious EPS file could use
    this to perform a DoS of Pillow in the open phase, before an image was accepted for opening.
    (CVE-2021-28677)

  - Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass
    controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.
    (CVE-2021-34552)

  - path_getbbox in path.c in Pillow before 9.0.0 improperly initializes ImagePath.Path. (CVE-2022-22815)

  - path_getbbox in path.c in Pillow before 9.0.0 has a buffer over-read during initialization of
    ImagePath.Path. (CVE-2022-22816)

  - PIL.ImageMath.eval in Pillow before 9.0.0 allows evaluation of arbitrary expressions, such as ones that
    use the Python exec method. A lambda expression could also be used, (CVE-2022-22817)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1288
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a392db43");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-pillow packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22817");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-pillow");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "python-pillow-2.0.0-19.h15.gitd1c6db8.eulerosv2r7"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pillow");
}
