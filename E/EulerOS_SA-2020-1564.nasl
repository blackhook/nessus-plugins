#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136267);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2019-18634", "CVE-2019-19232", "CVE-2019-19234");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : sudo (EulerOS-SA-2020-1564)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the sudo package installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - In PHP before 5.6.28 and 7.x before 7.0.13, incorrect
    handling of various URI components in the URL parser
    could be used by attackers to bypass hostname-specific
    URL checks, as demonstrated by
    evil.example.com:80#@good.example.com/ and
    evil.example.com:80?@good.example.com/ inputs to the
    parse_url function (implemented in the php_url_parse_ex
    function in ext/standard/url.c).(CVE-2019-19234)

  - In Sudo through 1.8.29, the fact that a user has been
    blocked (e.g., by using the ! character in the shadow
    file instead of a password hash) is not considered,
    allowing an attacker (who has access to a Runas ALL
    sudoer account) to impersonate any blocked
    user.(CVE-2019-19232)

  - In Sudo before 1.8.26, if pwfeedback is enabled in
    /etc/sudoers, users can trigger a stack-based buffer
    overflow in the privileged sudo process. (pwfeedback is
    a default setting in Linux Mint and elementary OS
    however, it is NOT the default for upstream and many
    other packages, and would exist only if enabled by an
    administrator.) The attacker needs to deliver a long
    string to the stdin of getln() in
    tgetpass.c.(CVE-2019-18634)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1564
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38e00cf5");
  script_set_attribute(attribute:"solution", value:
"Update the affected sudo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19234");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-18634");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["sudo-1.8.19p2-14.h7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");
}
