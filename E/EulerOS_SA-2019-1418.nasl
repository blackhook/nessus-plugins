#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124921);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187",
    "CVE-2016-7543",
    "CVE-2016-9401"
  );
  script_bugtraq_id(
    70103,
    70137,
    70152,
    70154
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"EulerOS Virtualization 3.0.1.0 : bash (EulerOS-SA-2019-1418)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bash package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - It was found that the fix for CVE-2014-6271 was
    incomplete, and Bash still allowed certain characters
    to be injected into other environments via specially
    crafted environment variables. An attacker could
    potentially use this flaw to override or bypass
    environment restrictions to execute shell commands.
    Certain services and applications allow remote
    unauthenticated attackers to provide environment
    variables, allowing them to exploit this
    issue.(CVE-2014-7169)

  - A denial of service flaw was found in the way bash
    handled popd commands. A poorly written shell script
    could cause bash to crash resulting in a local denial
    of service limited to a specific bash
    session.(CVE-2016-9401)

  - It was discovered that the fixed-sized redir_stack
    could be forced to overflow in the Bash parser,
    resulting in memory corruption, and possibly leading to
    arbitrary code execution when evaluating untrusted
    input that would not otherwise be run as
    code.(CVE-2014-7186)

  - An off-by-one error was discovered in the way Bash was
    handling deeply nested flow control constructs.
    Depending on the layout of the .bss segment, this could
    allow arbitrary execution of code that would not
    otherwise be executed by Bash.(CVE-2014-7187)

  - A flaw was found in the way Bash evaluated certain
    specially crafted environment variables. An attacker
    could use this flaw to override or bypass environment
    restrictions to execute shell commands. Certain
    services and applications allow remote unauthenticated
    attackers to provide environment variables, allowing
    them to exploit this issue.(CVE-2014-6271)

  - An arbitrary command injection flaw was found in the
    way bash processed the SHELLOPTS and PS4 environment
    variables. A local, authenticated attacker could use
    this flaw to exploit poorly written setuid programs to
    elevate their privileges under certain
    circumstances.(CVE-2016-7543)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1418
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?311a586e");
  script_set_attribute(attribute:"solution", value:
"Update the affected bash packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6271");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Qmail SMTP Bash Environment Variable Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["bash-4.2.46-30.h3.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash");
}
