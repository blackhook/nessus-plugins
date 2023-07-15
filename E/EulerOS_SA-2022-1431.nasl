#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159783);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-9791",
    "CVE-2019-9795",
    "CVE-2019-9810",
    "CVE-2019-9813",
    "CVE-2019-17017",
    "CVE-2019-17026"
  );
  script_xref(name:"IAVA", value:"2020-A-0002-S");
  script_xref(name:"IAVA", value:"2019-A-0089-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0007");

  script_name(english:"EulerOS 2.0 SP9 : mozjs60 (EulerOS-SA-2022-1431)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mozjs60 package installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Due to a missing case handling object types, a type confusion vulnerability could occur, resulting in a
    crash. We presume that with enough effort that it could be exploited to run arbitrary code. This
    vulnerability affects Firefox ESR < 68.4 and Firefox < 72. (CVE-2019-17017)

  - Incorrect alias information in IonMonkey JIT compiler for setting array elements could lead to a type
    confusion. We are aware of targeted attacks in the wild abusing this flaw. This vulnerability affects
    Firefox ESR < 68.4.1, Thunderbird < 68.4.1, and Firefox < 72.0.1. (CVE-2019-17026)

  - The type inference system allows the compilation of functions that can cause type confusions between
    arbitrary objects when compiled through the IonMonkey just-in-time (JIT) compiler and when the constructor
    function is entered through on-stack replacement (OSR). This allows for possible arbitrary reading and
    writing of objects during an exploitable crash. This vulnerability affects Thunderbird < 60.6, Firefox ESR
    < 60.6, and Firefox < 66. (CVE-2019-9791)

  - A vulnerability where type-confusion in the IonMonkey just-in-time (JIT) compiler could potentially be
    used by malicious JavaScript to trigger a potentially exploitable crash. This vulnerability affects
    Thunderbird < 60.6, Firefox ESR < 60.6, and Firefox < 66. (CVE-2019-9795)

  - Incorrect alias information in IonMonkey JIT compiler for Array.prototype.slice method may lead to missing
    bounds check and a buffer overflow. This vulnerability affects Firefox < 66.0.1, Firefox ESR < 60.6.1, and
    Thunderbird < 60.6.1. (CVE-2019-9810)

  - Incorrect handling of __proto__ mutations may lead to type confusion in IonMonkey JIT code and can be
    leveraged for arbitrary memory read and write. This vulnerability affects Firefox < 66.0.1, Firefox ESR <
    60.6.1, and Thunderbird < 60.6.1. (CVE-2019-9813)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1431
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b94e05e4");
  script_set_attribute(attribute:"solution", value:
"Update the affected mozjs60 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mozjs60");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "mozjs60-60.2.2-4.h2.r1.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozjs60");
}
