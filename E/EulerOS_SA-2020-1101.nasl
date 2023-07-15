#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133902);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-1348",
    "CVE-2019-1349",
    "CVE-2019-1350",
    "CVE-2019-1351",
    "CVE-2019-1352",
    "CVE-2019-1353",
    "CVE-2019-1354",
    "CVE-2019-1387",
    "CVE-2019-19604"
  );

  script_name(english:"EulerOS 2.0 SP5 : git (EulerOS-SA-2020-1101)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the git packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - A remote code execution vulnerability exists when Git
    for Visual Studio improperly sanitizes input, aka 'Git
    for Visual Studio Remote Code Execution Vulnerability'.
    This CVE ID is unique from CVE-2019-1349,
    CVE-2019-1350, CVE-2019-1352,
    CVE-2019-1387.(CVE-2019-1354)

  - A remote code execution vulnerability exists when Git
    for Visual Studio improperly sanitizes input, aka 'Git
    for Visual Studio Remote Code Execution Vulnerability'.
    This CVE ID is unique from CVE-2019-1349,
    CVE-2019-1350, CVE-2019-1354,
    CVE-2019-1387.(CVE-2019-1352)

  - A remote code execution vulnerability exists when Git
    for Visual Studio improperly sanitizes input, aka 'Git
    for Visual Studio Remote Code Execution Vulnerability'.
    This CVE ID is unique from CVE-2019-1350,
    CVE-2019-1352, CVE-2019-1354,
    CVE-2019-1387.(CVE-2019-1349)

  - An issue was found in Git before v2.24.1, v2.23.1,
    v2.22.2, v2.21.1, v2.20.2, v2.19.3, v2.18.2, v2.17.3,
    v2.16.6, v2.15.4, and v2.14.6. Recursive clones are
    currently affected by a vulnerability that is caused by
    too-lax validation of submodule names, allowing very
    targeted attacks via remote code execution in recursive
    clones.(CVE-2019-1387)

  - An issue was found in Git before v2.24.1, v2.23.1,
    v2.22.2, v2.21.1, v2.20.2, v2.19.3, v2.18.2, v2.17.3,
    v2.16.6, v2.15.4, and v2.14.6. The --export-marks
    option of git fast-import is exposed also via the
    in-stream command feature export-marks=... and it
    allows overwriting arbitrary paths.(CVE-2019-1348)

  - Arbitrary command execution is possible in Git before
    2.20.2, 2.21.x before 2.21.1, 2.22.x before 2.22.2,
    2.23.x before 2.23.1, and 2.24.x before 2.24.1 because
    a 'git submodule update' operation can run commands
    found in the .gitmodules file of a malicious
    repository.(CVE-2019-19604)

  - A remote code execution vulnerability exists when Git
    for Visual Studio improperly sanitizes input, aka 'Git
    for Visual Studio Remote Code Execution Vulnerability'.
    This CVE ID is unique from CVE-2019-1349,
    CVE-2019-1352, CVE-2019-1354,
    CVE-2019-1387.(CVE-2019-1350)

  - A tampering vulnerability exists when Git for Visual
    Studio improperly handles virtual drive paths, aka 'Git
    for Visual Studio Tampering
    Vulnerability'.(CVE-2019-1351)

  - An issue was found in Git before v2.24.1, v2.23.1,
    v2.22.2, v2.21.1, v2.20.2, v2.19.3, v2.18.2, v2.17.3,
    v2.16.6, v2.15.4, and v2.14.6. When running Git in the
    Windows Subsystem for Linux (also known as 'WSL') while
    accessing a working directory on a regular Windows
    drive, none of the NTFS protections were
    active.(CVE-2019-1353)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1101
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee0cf314");
  script_set_attribute(attribute:"solution", value:
"Update the affected git packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19604");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:git-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["git-2.23.0-1.h4.eulerosv2r7",
        "git-core-2.23.0-1.h4.eulerosv2r7",
        "git-core-doc-2.23.0-1.h4.eulerosv2r7",
        "perl-Git-2.23.0-1.h4.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git");
}
